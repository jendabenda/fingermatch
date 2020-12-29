"""
FingerMatch

IDA plugin for collecting functions, data, types and comments from analysed binaries
and fuzzy matching them in another binaries.

autor: Jan Prochazka
licence: none, public domain
home: https://github.com/jendabenda/fingermatch


Collection process
 * collect functions - function traces and function referencees
 * collect data - hashes and data references
 * collect types
 * collect comments
 * collect metadata of all above
 * save to FingerMatch database


Matching process
 * load fingerprints from FingerMatch database
 * function traces and data hashes are matched as candidates
 * graph of guesses is created from candidates and references between them
 * unambigous candidates for functions and data locations are resolved
 * algorithm is tuned to output low number of false positives
 * names, types and comments are applied to matched items
 * matched items are written into json file
 * unmatched guesses are writen into json file in format
   { place_ea: { source_ea: [ name_a, name_b, ...], ... }, ... }


Functions fingerprints
 * 32 byte signature - only the first byte of instructions and immediate values
   are saved
 * function trace - structure designed for fast fuzzy matching, details bellow
 * code and data references to other functions / data
 * name, flags, types and comments are also saved

Data fingerprints
 * 32 byte signature - the first 32 bytes, pointers are ignored
 * FNV-1a hash of data items
 * name, flags, types and comments are also saved


Function traces are fingerprint parts for matching functions. They are designed so they
match the same function, but the function can have shuffled basic block starts, different
register allocation and instruction scheduling within their basic block. Also matching
should be fast indeed, designed for fail fast strategy and efficient exploration of unknown
areas. Basically trace is series of hashes with references. One example is

trace = [(12, 0xaf840b37c19a863, 'cscdi', True, 0), (...), (...)]
external_refs = [...]

Above example is a function consiting of 3 control flow blocks.
The first one has 12 instructions, their cumulative (and commutative) hash
is 0xaf840b37c19a863, there are 1 external data reference, 2 external code
references and one internal code reference ('cscdi'). Internal references are
immediately pushed onto matcher stack. True means that matcher should explore
instructions after the last one (last instruction is likely conditional
branch) and the last 0 informs matcher to not remove anyting from matcher stack.
For details see fingerprint_function and match_function_candidates.


Todo
 * Aho-Corasic style pattern trie links for faster unknown bytes matching
 * data reference linking
 * rewrite fdb merging
"""

import sys
import json
import bisect
import math
import importlib
import gzip
import io
import re
import pickle
from collections import namedtuple

import idaapi as ida


signature_size = 32  # length of function/data signature
strong_match_fn_size = 16  # minimum instructions to consider function a strong match
strong_match_data_size = 10  # minimum size in bytes to consider data a strong match
useless_bytes = set([0x00, 0x01, 0x02, 0x04, 0x08, 0x7f, 0x80, 0xff])  # useless bytes for data fingerprinting
useful_bytes_count = 3  # minimum number of useful bytes for data fingerprinting
max_candidates = 100  # maximum number of candidates per one offset


class UserInterrupt(Exception):
    """
    Thrown when user cancels running operation
    """
    pass


class OperationFailed(Exception):
    """
    Thrown when a critical operation failed
    """
    pass


class IntervalTree:
    """
    Interval "tree", assuming small ammount of overlaps.
    Finds overlapping intevals and merges them into parent one. One level nesting only.
    """

    def __init__(self, intervals):
        """
        Build interval data structure
        """

        intervals = sorted(intervals, key=lambda interval: interval[0])

        # find overlapping intervals
        overlaps = []
        starts = []
        if intervals:
            overlap = []
            overlap_end = intervals[0][1]
            for interval in intervals:
                start, end, data = interval
                if overlap_end > start:
                    overlap_end = max(overlap_end, end)
                    overlap.append(interval)
                else:
                    overlaps.append((overlap[0][0], overlap_end, overlap))
                    starts.append(overlap[0][0])
                    overlap = [interval]
                    overlap_end = end
            overlaps.append((overlap[0][0], overlap_end, overlap))
            starts.append(overlap[0][0])

        self.starts = starts
        self.overlaps = overlaps


    def find_point(self, point):
        """
        Find intervals containing given point and return interval data
        """

        index = bisect.bisect(self.starts, point) - 1
        if index == -1:
            return []

        start, end, intervals = self.overlaps[index]
        return [data for start, end, data in intervals if start <= point < end]


    def find_range(self, start_point, end_point):
        """
        Find intervals overlapping with given range
        """

        start_index = max(0, bisect.bisect(self.starts, start_point) - 1)
        end_index = bisect.bisect(self.starts, end_point)

        return [
            data
            for start, end, intervals in self.overlaps[start_index:end_index]
            for start, end, data in intervals
            if start_point <= start < end_point or start <= start_point < end
        ]


    def find(self, start, end=None):
        """
        Finds overlapping intervals with given point or range
        """

        if end is None:
            return self.find_point(start)
        else:
            return self.find_range(start, end)


class PatternNode:
    """
    Node for pattern trie
    """

    __slots__ = ['edges', 'data']

    def __init__(self):
        self.edges = None
        self.data = None


class PatternTrie:
    """
    Match multple patterns against given data at once
    """

    def __init__(self):
        self.root = PatternNode()


    def add(self, pattern, data):
        """
        Add pattern to trie
        """

        # walk the graph for given key
        node = self.root
        for symbol in pattern:
            if node.edges is None:
                node.edges = {}

            if symbol in node.edges:
                node = node.edges[symbol]
            else:
                next_node = PatternNode()
                node.edges[symbol] = next_node
                node = next_node

        # add value to leaf
        if node.data is None:
            node.data = []
        node.data.append(data)


    def match(self, symbol, nodes=None):
        """
        Incrementaly match stored patterns against given symbolS
        """

        if nodes is None:
            nodes = [self.root]

        next_nodes = []
        data = []
        for node in nodes:
            if node.edges is not None:
                # strict match
                if symbol in node.edges:
                    next_node = node.edges[symbol]
                    next_nodes.append(next_node)
                    if next_node.data is not None:
                        data.extend(next_node.data)

                # any match
                if None in node.edges:
                    next_node = node.edges[None]
                    next_nodes.append(next_node)
                    if next_node.data is not None:
                        data.extend(next_node.data)

        return data, next_nodes


def progress(iterable=None):
    """
    Make computation responsive
    """

    if iterable is None:
        if ida.user_cancelled():
            raise UserInterrupt()
    else:
        for item in iterable:
            yield item
            if ida.user_cancelled():
                raise UserInterrupt()


fnv_start = 0xcbf29ce484222325
def fnv_hash(hash, num):
    """
    Compute FNV1a hash
    """

    return ((hash ^ num) * 0x100000001b3) & 0xffffffffffffffff


def argsort(sequence):
    """
    Return indices of sorted items
    """

    return sorted(range(len(sequence)), key=sequence.__getitem__)


def list_segments():
    """
    Return segments available for fingerprinting
    """

    segment_types = (ida.SEG_CODE, ida.SEG_DATA)
    segments = []
    segment = ida.get_first_seg()
    while segment is not None:
        if segment.type in segment_types:
            segments.append((ida.get_segm_name(segment), segment.start_ea, segment.end_ea, segment.type))
        segment = ida.get_next_seg(segment.start_ea)

    return segments


def is_address_fingerprintable(ea, segments):
    """
    Test if address is usable for fingerprinting
    """

    return any(1 for name, start, end, type in segments if start <= ea < end)


def escape_cpp(match):
    """
    Escape cpp template chars
    """

    text = match.group(0)
    text = text.replace('_fme_', '_fme__fme_')
    text = text.replace('<', '_fme_a_')
    text = text.replace('>', '_fme_b_')
    text = text.replace(',', '_fme_c_')
    text = text.replace('*', '_fme_d_')
    text = text.replace('&', '_fme_e_')
    text = text.replace(':', '_fme_f_')
    text = text.replace(' ', '_fme_g_')
    text = text.replace('-', '_fme_h_')
    text = text.replace('"', '_fme_i_')
    text = text.replace("'", '_fme_j_')

    return text


def unescape_type(text):
    """
    Unescape cpp names
    """

    text = text.replace('_fme_a_', '<')
    text = text.replace('_fme_b_', '>')
    text = text.replace('_fme_c_', ',')
    text = text.replace('_fme_d_', '*')
    text = text.replace('_fme_e_', '&')
    text = text.replace('_fme_f_', ':')
    text = text.replace('_fme_g_', ' ')
    text = text.replace('_fme_h_', '-')
    text = text.replace('_fme_i_', '"')
    text = text.replace('_fme_j_', "'")
    text = text.replace('_fme__fme_', '_fme_')

    return text


def escape_type(text):
    """
    Escape cpp names
    """

    escape_re = re.compile('(<[^<>]*>)')
    while '<' in text and '>' in text:
        text = escape_re.sub(escape_cpp, text)

    return text


def insert_function_name(tdecl, name):
    """
    Insert function name into tupe declaration
    """

    brackets = 0
    for n, c in enumerate(reversed(tdecl)):
        if c == ')':
            brackets += 1
        elif c == '(':
            brackets -= 1
            if brackets == 0 and n > 0:
                return '{} {}{}'.format(tdecl[:-n - 1], name, tdecl[-n - 1:])

    return tdecl


def collect_types():
    """
    Return types used for given nodes
    """

    # collect comments
    types = []
    ordinal_count = ida.get_ordinal_qty(None)
    print('collecting types  ')
    for ordinal in progress(range(1, ordinal_count + 1)):
        ttuple = ida.get_numbered_type(None, ordinal)
        if ttuple is None:
            continue

        name = ida.get_numbered_type_name(None, ordinal)
        tinfo = ida.tinfo_t()
        tinfo.deserialize(None, *ttuple[:3])
        tdecl = tinfo._print(None, ida.PRTYPE_1LINE | ida.PRTYPE_SEMI | ida.PRTYPE_TYPE)
        if ida.parse_decl(tinfo, None, escape_type(tdecl), ida.PT_SIL) is None:
            continue

        name = ida.get_numbered_type_name(None, ordinal)
        sid = ida.get_struc_id(name)
        enum = ida.get_enum(name)

        if sid != ida.BADADDR:
            # structures
            struct = ida.get_struc(sid)
            members = []
            for m in range(struct.memqty):
                member = struct.get_member(m)
                members.append({
                    'name': ida.get_member_name(member.id),
                    'cmt': ida.get_member_cmt(member.id, False),
                    'cmt_rep': ida.get_member_cmt(member.id, True),
                    'offset': member.soff,
                })
            types.append({
                'name': name,
                'type': 'struct',
                'tdecl': tdecl,
                'cmt': ida.get_struc_cmt(sid, False),
                'cmt_rep': ida.get_struc_cmt(sid, True),
                'members': members,
                'sync': ida.is_autosync(name, ttuple[0]),
            })
        elif enum != ida.BADADDR:
            members = []
            bmask = ida.get_first_bmask(enum)
            if bmask != ida.DEFMASK:
                # bitfields
                while bmask != ida.DEFMASK:
                    members.append({
                        'name': ida.get_bmask_name(enum, bmask),
                        'bmask': bmask,
                        'cmt': ida.get_bmask_cmt(enum, bmask, False),
                        'cmt_rep': ida.get_bmask_cmt(enum, bmask, True),
                    })
                    bmask = ida.get_next_bmask(enum, bmask)
                type = 'bitfield'
            else:
                # enums
                value = ida.get_first_enum_member(enum)
                while value != ida.BADADDR:
                    cid, serial = ida.get_first_serial_enum_member(enum, value, ida.DEFMASK)
                    main_cid = cid
                    while cid != ida.BADNODE:
                        members.append({
                            'name': ida.get_enum_member_name(cid),
                            'value': value,
                            'cmt': ida.get_enum_member_cmt(cid, False),
                            'cmt_rep': ida.get_enum_member_cmt(cid, True),
                        })
                        cid, serial = ida.get_next_serial_enum_member(serial, main_cid)
                    value = ida.get_next_enum_member(enum, value)
                type = 'enum'
            types.append({
                'name': name,
                'type': type,
                'tdecl': tdecl,
                'cmt': ida.get_enum_cmt(enum, False),
                'cmt_rep': ida.get_enum_cmt(enum, True),
                'members': members,
                'sync': ida.is_autosync(name, ttuple[0]),
            })
        else:
            # plain types
            types.append({
                'name': name,
                'type': 'type',
                'tdecl': tdecl,
                'sync': ida.is_autosync(name, ttuple[0]),
            })

    return types


def import_types(types):
    """
    Import types from definitions.
    IDA cannot cope with cpp names so they need to be escaped first and then
    renamed back after all types are applied.
    """

    # collect existing types
    existing = {}
    ordinal_count = ida.get_ordinal_qty(None)
    for ordinal in range(1, ordinal_count + 1):
        name = ida.get_numbered_type_name(None, ordinal)
        if name is not None:
            existing[name] = ordinal

    # import types
    tindex = None
    imported = {}
    new_imported = {}
    print('importing types')
    while True:
        for n, type_dict in enumerate(types):
            name = type_dict['name']
            tdecl = type_dict['tdecl']
            type = type_dict['type']
            sync = type_dict['sync']
            if name in imported:
                continue

            tdecl_escaped = escape_type(tdecl)
            name_escaped = escape_type(name)

            tinfo = ida.tinfo_t()
            if ida.parse_decl(tinfo, None, tdecl_escaped, ida.PT_SIL) is None:
                continue

            if name in existing:
                tindex = existing[name]
            elif tindex is None:
                tindex = ida.alloc_type_ordinal(None)

            ttuple = tinfo.serialize()
            if ida.set_numbered_type(None, tindex, ida.NTF_REPLACE, name_escaped, *ttuple) != ida.TERR_OK:
                continue

            new_imported[name] = (name_escaped, tindex, tinfo)
            tindex = None

            if sync:
                ida.import_type(None, -1, name_escaped, ida.IMPTYPE_OVERRIDE)

            if type == 'enum':
                # apply enum comments
                enum = ida.get_enum(name_escaped)
                if enum is not None:
                    ida.set_enum_cmt(enum, type_dict['cmt'], False)
                    ida.set_enum_cmt(enum, type_dict['cmt_rep'], True)

                    # apply enum member comments
                    for member in type_dict['members']:
                        cid = ida.get_enum_member_by_name(member['name'])
                        ida.set_enum_member_cmt(cid, member['cmt'], False)
                        ida.set_enum_member_cmt(cid, member['cmt_rep'], True)
            elif type == 'bitfield':
                # apply bitfield comments
                enum = ida.get_enum(name_escaped)
                if enum is not None:
                    ida.set_enum_cmt(enum, type_dict['cmt'], False)
                    ida.set_enum_cmt(enum, type_dict['cmt_rep'], True)

                    # apply bitfield member comments
                    for member in type_dict['members']:
                        ida.set_bmask_cmt(enum, member['bmask'], member['cmt'], False)
                        ida.set_bmask_cmt(enum, member['bmask'], member['cmt_rep'], True)
            elif type == 'struct':
                # apply struct comments
                sid = ida.get_struc_id(name_escaped)
                struct = ida.get_struc(sid)
                if struct is not None:
                    ida.set_struc_cmt(sid, type_dict['cmt'], False)
                    ida.set_struc_cmt(sid, type_dict['cmt_rep'], True)

                    # apply struct member comments
                    for m, member in zip(range(struct.memqty), type_dict['members']):
                        mptr = struct.get_member(m)
                        ida.set_member_cmt(mptr, member['cmt'], False)
                        ida.set_member_cmt(mptr, member['cmt_rep'], True)

        if not new_imported:
            break

        imported.update(new_imported)
        new_imported = {}

    return imported


def import_types_rename(imported):
    """
    Renamed escaped types to original form
    """

    renamed = set()
    while True:
        new_renamed = set()
        for name, (name_escaped, tindex, tinfo) in imported.items():
            if name in renamed:
                continue

            if name != name_escaped:
                if tinfo.set_numbered_type(None, tindex, ida.NTF_REPLACE, unescape_type(name_escaped)) == ida.TERR_OK:
                    new_renamed.add(name)

        if not new_renamed:
            break
        renamed |= new_renamed


def is_reference(source, target):
    """
    Check if source refers to target
    """

    if ida.getseg(target) is None:
        return False

    # code references
    ref = ida.get_first_cref_from(source)
    while ref != ida.BADADDR:
        if ref == target and ref != ida.BADADDR:
            return True
        ref = ida.get_next_cref_from(source, ref)

    # data references
    ref = ida.get_first_dref_from(source)
    while ref != ida.BADADDR:
        if ref == target and ref != ida.BADADDR:
            return True
        ref = ida.get_next_dref_from(source, ref)

    return False


def fingerprint_instruction(ea, instruction, check_refs):
    """
    Return fingerprint of an instruction
    """

    refs = []
    instruction_hash = fnv_start
    instruction_hash = fnv_hash(instruction_hash, instruction.itype)
    ops = instruction.ops
    for n in range(8):
        operand = ops[n]
        otype = operand.type
        if otype == ida.o_void:
            break

        instruction_hash = fnv_hash(instruction_hash, n)
        instruction_hash = fnv_hash(instruction_hash, otype)

        if otype == ida.o_imm:
            instruction_hash = fnv_hash(instruction_hash, operand.value)
        elif otype == ida.o_displ:
            instruction_hash = fnv_hash(instruction_hash, operand.addr)
        else:
            instruction_hash = fnv_hash(instruction_hash, 0x12345678)

        if otype == ida.o_mem:
            if not check_refs or is_reference(ea, operand.addr):
                refs.append(('d', operand.addr))
            else:
                refs.append(None)
        elif otype == ida.o_imm:
            if not check_refs or is_reference(ea, operand.value):
                refs.append(('d', operand.value))
            else:
                refs.append(None)
        elif otype == ida.o_near or otype == ida.o_far:
            if not check_refs or is_reference(ea, operand.addr):
                refs.append(('c', operand.addr))
            else:
                refs.append(None)

    return instruction_hash, refs


def fingerprint_function(fn_start, fn_end):
    """
    Compute function trace
    """

    # function trace compilation
    comments = {}
    comments_rep = {}
    trace = []
    trace_block_count = 0
    trace_instruction_count = 0
    trace_refs = []
    blocks = []
    block_start = None
    block_end = None
    block_next = None
    block_refs = []
    block_instruction_count = 0
    block_hash = 0
    block_stack_pops = 0
    stack = [(fn_start, True)]
    instruction = ida.insn_t()
    while stack:
        ea, flow = stack.pop()
        seen = any(start <= ea < end for start, end in blocks)
        seen_current = block_start is not None and block_start <= ea < block_end

        # append trace
        if not flow or seen:
            if block_instruction_count:
                if trace:
                    prev = trace[-1]
                    trace[-1] = (prev[0], prev[1], prev[2], prev[3], prev[4] + block_stack_pops)
                trace.append((
                    block_instruction_count,
                    block_hash,
                    ''.join(block_refs),
                    block_next,
                    0))
                trace_block_count += 1
                blocks.append((block_start, block_end))
                block_start = None
                block_end = None
                block_next = None
                block_refs = []
                block_instruction_count = 0
                block_hash = 0
                block_stack_pops = 0

        # don't follow already explored path
        if seen or seen_current:
            block_stack_pops += 1
            continue

        # mark start of a block if we don't have it
        if block_start is None:
            block_start = ea

        # decode instruction
        size = ida.decode_insn(instruction, ea)
        if size == 0:
            block_next = False
            block_end = ea
            continue

        next_ea = ea + size
        block_end = next_ea

        # fingerprint instruction
        instruction_hash, refs = fingerprint_instruction(ea, instruction, check_refs=True)
        block_hash = (block_hash + instruction_hash) & 0xffffffffffffffff
        position = (trace_block_count, instruction_hash)
        trace_instruction_count += 1
        block_instruction_count += 1
        block_next = ida.is_flow(ida.get_flags(next_ea))

        # collect comments
        comment = ida.get_cmt(ea, False)
        if comment is not None:
            cmts = comments.setdefault(position, [])
            cmts.append(comment)
        comment = ida.get_cmt(ea, True)
        if comment is not None:
            cmts = comments_rep.setdefault(position, [])
            cmts.append(comment)

        # follow control flow
        internal_crefs = []
        for ref_tuple in refs:
            if ref_tuple is None:
                # skip reference
                block_refs.append('s')
            elif fn_start <= ref_tuple[1] < fn_end:
                # internal reference
                rtype, ref = ref_tuple
                block_refs.append('i')
                internal_crefs.append((ref, False))
            else:
                # external reference
                rtype, ref = ref_tuple
                block_refs.append(rtype)
                trace_refs.append((None, ref))

        stack.extend(internal_crefs)
        if block_next:
            stack.append((next_ea, len(internal_crefs) == 0))

    # append trace
    if trace:
        prev = trace[-1]
        trace[-1] = (prev[0], prev[1], prev[2], prev[3], prev[4] + block_stack_pops)
    if block_instruction_count:
        trace.append((
            block_instruction_count,
            block_hash,
            ''.join(block_refs),
            False,
            0))

    return tuple(trace), trace_instruction_count, trace_refs, comments, comments_rep


def fingerprint_functions(segments):
    """
    Create fingerprints for functions
    """

    log2 = math.log(2)

    instruction = ida.insn_t()
    tinfo = ida.tinfo_t()
    count = ida.get_func_qty()
    functions = []
    print('  functions  ')
    for n in progress(range(count)):
        # gather info
        function = ida.getn_func(n)
        fn_start = function.start_ea
        fn_end = function.end_ea
        fn_flags = ida.get_flags(fn_start)
        fn_name = ida.get_name(fn_start)
        if ida.get_tinfo(tinfo, fn_start):
            fn_type = tinfo._print(None, ida.PRTYPE_1LINE | ida.PRTYPE_SEMI)
        else:
            fn_type = None
        fn_flags = function.flags

        ida.show_auto(fn_start, ida.AU_USED)

        if is_address_fingerprintable(fn_start, segments):
            # signature
            size = min(fn_end - fn_start, signature_size)
            signature = signature_size * [None]
            signature_bytes = ida.get_bytes(fn_start, size)
            n = 0
            maxn = 0
            while n < size:
                # first instruction byte
                signature[n] = signature_bytes[n]
                instruction_size = ida.decode_insn(instruction, fn_start + n)
                maxn = n + instruction_size

                # immediate values in operands
                for op in instruction.ops:
                    op_size = 0
                    if op.type == ida.o_imm:
                        value = abs(op.value)
                        if value > 0:
                            op_size = math.ceil(int(math.log(value) / log2 + 1) / 8)
                    op_size = int(min(op_size, instruction_size - op.offb))
                    for o in range(n + op.offb, min(n + op.offb + op_size, signature_size)):
                        signature[o] = signature_bytes[o]

                n += instruction_size
            signature = tuple(signature[:maxn])

            # function trace
            trace, instruction_count, refs, comments, comments_rep = fingerprint_function(fn_start, fn_end)

            if not trace:
                continue
        else:
            signature = None
            trace = None
            refs = []

        # save information
        functions.append({
            'ea': fn_start,
            'type': 'function',
            'name': fn_name,
            'size': fn_end - fn_start,
            'tdecl': fn_type,
            'signature': tuple(signature) if signature is not None else None,
            'fingerprint': tuple(trace) if trace is not None else None,
            'refs': refs,
            'cmt': ida.get_func_cmt(function, False),
            'cmt_rep': ida.get_func_cmt(function, True),
            'code_cmt': comments,
            'code_cmt_rep': comments_rep,
            'user': not ida.has_dummy_name(fn_flags),
            'flags':  fn_flags,
            'public': ida.is_public_name(fn_start),
            'weak': ida.is_weak_name(fn_start),
            'strong': instruction_count >= strong_match_fn_size})
    ida.show_auto(0, ida.AU_NONE)

    return functions


def get_external_reference(ea, block_start, block_end):
    """
    Get forward references
    """

    xb = ida.xrefblk_t()
    ref = xb.first_from(ea, ida.XREF_ALL)
    while ref:
        to = xb.to
        if block_start <= to < block_end:
            pass
        elif ida.getseg(to) is not None:
            return to

        ref = xb.next_from()


def fingerprint_data_places(segments):
    """
    Create fingerprints for data
    """

    tinfo = ida.tinfo_t()
    print('  data  ')
    data = []
    count = ida.get_nlist_size()
    for n in progress(range(count)):
        # collect information
        data_start = ida.get_nlist_ea(n)
        ida.show_auto(data_start, ida.AU_USED)

        flags = ida.get_flags(data_start)
        if not ida.is_data(flags):
            continue

        name = ida.get_nlist_name(n)
        if ida.get_tinfo(tinfo, data_start):
            data_type = tinfo._print(None, ida.PRTYPE_1LINE | ida.PRTYPE_SEMI)
        else:
            data_type = None
        data_size = ida.get_item_size(data_start)
        data_bytes = ida.get_bytes(data_start, data_size)

        # collect external references
        data_refs = False
        for ea in range(data_start, data_start + data_size):
            ref = get_external_reference(ea, data_start, data_start + data_size)
            if ref is not None:
                data_refs = True

        # fingerprint
        if (is_address_fingerprintable(data_start, segments) and
            not data_refs and
            sum(1 for byte in data_bytes if byte not in useless_bytes) >= useful_bytes_count):
            signature = tuple(data_bytes[:signature_size])
            fingerprint = fnv_start
            for byte in data_bytes:
                fingerprint = fnv_hash(fingerprint, byte)
        else:
            signature = None
            fingerprint = None

        # collect comments
        comments = {}
        comments_rep = {}
        comment = ida.get_cmt(data_start, False)
        if comment is not None:
            comments[0] = comment
        comment = ida.get_cmt(data_start, True)
        if comment is not None:
            comments_rep[0] = comment

        # save information
        data.append({
            'name': name,
            'type': 'data',
            'ea': data_start,
            'tdecl': data_type,
            'size': data_size,
            'signature': signature,
            'fingerprint': fingerprint,
            'cmt': comments,
            'cmt_rep': comments_rep,
            'refs': {},
            'user': not ida.has_dummy_name(flags),
            'public': ida.is_public_name(data_start),
            'weak': ida.is_weak_name(data_start),
            'strong': data_size >= strong_match_data_size})
    ida.show_auto(0, ida.AU_NONE)

    return data


def ref_to_symbol(ref, nodes):
    """
    Converts reference to symbolic value
    """

    if not nodes:
        return None, None

    # pick node with the smallest size
    node = sorted(nodes, key=lambda node: node['size'])[0]

    ref_type = node['type']
    if ref_type == 'data':
        return node['name'], ref - node['ea']
    elif ref_type == 'function':
        return node['name'], None
    else:
        assert False, 'unknown node type {}'.format(ref_type)


def resolve_refs(refs, node_intervals, unknowns):
    """
    Resolve node references
    """

    resolved = []
    for pos, ref in refs:
        nodes = node_intervals.find(ref)
        name, offset = ref_to_symbol(ref, nodes)
        if name is None:
            name = unknowns.setdefault(ref, (len(unknowns),))

        resolved.append((pos, name, offset))

    return resolved


class SaveUnpickler(pickle.Unpickler):
    """
    Restricts unpickling to increase security.
    """

    def find_class(self, module, name):
        """
        Restrict classes that can be unpickled.
        """

        if name not in ('PatternTrie', 'PatternNode'):
            raise pickle.UnpicklingError('Unknown object to load {}.{}'.format(module, name))

        return super().find_class(module, name)


def save_fdb(filename, db):
    """
    Save fingerprints into a filename
    """

    with io.BufferedWriter(gzip.open(filename, 'wb')) as fd:
        pickle.dump(db, fd, 3)  # Python 3.0+ compatible


def load_fdb(filename):
    """
    Load fingermatch database
    """

    with io.BufferedReader(gzip.open(filename, 'rb')) as fd:
        return SaveUnpickler(fd).load()


def build_signature_matcher(nodes):
    """
    Build datastructure for matching signatures
    """

    print('building matching structures  ')
    patterns = PatternTrie()
    patterns_unknown = PatternTrie()
    for n, node in progress(enumerate(nodes)):
        if node['signature'] is not None:
            patterns.add(node['signature'], node)
            if node['strong']:
                patterns_unknown.add(node['signature'], node)

    return patterns, patterns_unknown


def verify_strongness(nodes):
    """
    Verify if strong nodes are unambiguous, possibly removing strong attribute
    """

    print('  checking uniqueness  ')
    fingerprints = {}
    for n, node in progress(enumerate(nodes)):
        fprint = node['fingerprint']
        if fprint in fingerprints:
            node['strong'] = False
            fingerprints[fprint]['strong'] = False
        else:
            fingerprints[fprint] = node


def collect(fingerdb_path, annotations_path):
    """
    Create fingerprints for whole db
    """

    print('collecting')
    segments = list_segments()

    # fingerprinting
    nodes = []
    nodes.extend(fingerprint_functions(segments))
    nodes.extend(fingerprint_data_places(segments))

    function_count = 0
    data_count = 0
    for node in nodes:
        if node['type'] == 'function':
            function_count += 1
        elif node['type'] == 'data':
            data_count += 1

    print('  function count  {}'.format(function_count))
    print('  data count  {}'.format(data_count))

    types = None

    # save annotations
    if annotations_path is not None:
        print('saving annotations to  {}'.format(annotations_path))
        save_annotations(nodes, annotations_path)

    # save fingerdb
    if fingerdb_path is not None:
        # resolve references
        node_intervals = IntervalTree([(node['ea'], node['ea'] + node['size'], node) for node in nodes])
        print('  resolving references  ')
        unknowns = {}
        reference_count = 0
        for n, node in progress(enumerate(nodes)):
            node['refs'] = resolve_refs(node['refs'], node_intervals, unknowns)
            reference_count += len(node['refs'])
        print('postprocessing')
        print('  reference count  {}'.format(reference_count))
        print('  reference unknowns  {}'.format(len(unknowns)))

        # verify node strongness (must have unique fingerprint)
        verify_strongness(nodes)

        # signature matching
        patterns, patterns_unknown = build_signature_matcher(nodes)

        # name matching
        names = {}
        for node in nodes:
            names[node['name']] = node

        # remove things not used for matching
        for node in nodes:
            del node['ea']

        # collect types used for fingerprinted functions and data
        types = collect_types()

        # pickle fingerprints
        print('saving fingerprints to  {}'.format(fingerdb_path))
        save_fdb(fingerdb_path, {
            'version': 0,
            'nodes': nodes,
            'patterns': patterns,
            'patterns_unknown': patterns_unknown,
            'names': names,
            'types': types,
        })

    print('done\n')

    return nodes, types


def save_annotations(nodes, filename):
    """
    Save annotations into jsonl file
    """

    with open(filename, 'w') as fd:
        for node in nodes:
            size = node['size'] if node['type'] == 'data' else 1
            start = node['ea']
            end = start + size
            json.dump(((start, end), node['name']), fd)
            fd.write('\n')


def load_annotations(filename):
    """
    Load annotations from jsonl file
    """

    annotations = []
    with open(filename) as fd:
        for line in fd:
            record = json.loads(line)
            annotations.append(GuessNode(ea=tuple(record[0]), name=record[1]))

    return set(annotations)


# Graph of guesses
GuessNode = namedtuple('GuessNode', ('ea', 'name'))
Guess = namedtuple('Guess', ('node', 'refs', 'tag'))

# Graph group tags
guess_weak = 0
guess_strong = 1


def match_refs(trace_refs, candidate, names):
    """
    Match forward refrences for a candidate
    """

    refs = []
    for mdst, (cpos, cdst, cdst_offset) in zip(trace_refs, candidate['refs']):
        cnode = names.get(cdst)
        if cnode is None:
            cea = mdst
            csize = 1
        elif cnode['type'] == 'data':
            if cdst_offset == 0:
                cea = mdst
            else:
                cea = mdst - cdst_offset
            csize = cnode['size']
        elif cnode['type'] == 'function':
            cea = mdst
            csize = 1
        else:
            assert False, 'unknown node type {}'.cnode['type']

        refs.append(GuessNode((cea, cea + csize), cdst))

    return refs


def match_function_candidates(start, end, candidates, guesses, position_to_ea, names):
    """
    Match list of candidates on specified binary location
    """

    instruction = ida.insn_t()

    # group candidates to imporove matching performance
    candidate_groups = {}
    for candidate in candidates:
        group = candidate_groups.setdefault(candidate['fingerprint'], [])
        group.append(candidate)

    # filter candidates by function trace
    survivals = []
    for ctrace, candidate_members in candidate_groups.items():
        ctrace_blocks = len(ctrace)
        cposition_to_ea = {}

        # function trace compilation and matching
        survived = True
        trace_block_index = 0
        trace_refs = []
        stack = [start]
        while stack:
            ea = stack.pop()
            if not (start <= ea < end):
                mismatch_reason = 'out of allowed range'
                survived = False
                break
            if trace_block_index >= ctrace_blocks:
                mismatch_reason = 'too many trace blocks'
                survived = False
                break
            ccount, chash, cref_types, cnext, cpops = ctrace[trace_block_index]

            # fingerprint trace block
            block_ref_count = 0
            block_hash = 0
            cref_count = len(cref_types)
            cref_type_index = 0
            mismatch_reason = None
            for n in range(ccount):
                # decode instruction
                size = ida.decode_insn(instruction, ea)
                if size == 0:
                    mismatch_reason = 'invalid instruction inside trace block {}'.format(trace_block_index)
                    survived = False
                    break

                # fingerprint instruction
                instruction_hash, mrefs = fingerprint_instruction(ea, instruction, check_refs=False)
                block_hash = (block_hash + instruction_hash) & 0xffffffffffffffff
                cposition_to_ea[(trace_block_index, instruction_hash)] = ea

                # add refs to trace
                for r, (rtype, mref) in enumerate(mrefs):
                    if cref_type_index + r >= cref_count:
                        mismatch_reason = 'block {} has more refs than expected'.format(trace_block_index)
                        survived = False
                        break

                    cref_type = cref_types[cref_type_index + r]
                    if cref_type == 's':
                        pass
                    elif cref_type == 'i':
                        stack.append(mref)
                    elif cref_type in 'cd':
                        if rtype != cref_type:
                            mismatch_reason = 'ref type mismatch at {}'.format((trace_block_index, r))
                            survived = False
                            break
                        trace_refs.append(mref)
                    else:
                        assert False, 'unknown ref type {} at {}'.format(cref_type, (trace_block_index, r))

                    block_ref_count += 1

                if not survived:
                    break

                cref_type_index = block_ref_count
                ea += size
            if not survived:
                break

            # check block hash
            if block_hash != chash:
                mismatch_reason = 'block {} has mismatched hash'.format(trace_block_index)
                survived = False
                break

            # check ref counts
            if block_ref_count != len(cref_types):
                mismatch_reason = 'ref counts does not match in block {}'.format(trace_block_index)
                survived = False
                break

            # advance to next block
            if cnext:
                stack.append(ea)

            # clear stack
            if len(stack) < cpops:
                mismatch_reason = 'matching stack is missing refs at block {}'.format(trace_block_index)
                survived = False
                break
            if cpops:
                stack = stack[:-cpops]

            trace_block_index += 1

        # was candidate succesful match?
        if survived:
            survivals = candidate_members
            break

    if not survived:
        return
    candidates = survivals

    # todo remember candidates behind limit
    candidates = candidates[:max_candidates]

    # update position to ea map
    for candidate in candidates:
        position_to_ea[(candidate['name'], start)] = cposition_to_ea

    # update guesses
    for candidate in candidates:
        node = GuessNode((start, start + 1), candidate['name'])
        tag = guess_strong if candidate['strong'] else guess_weak
        refs = match_refs(trace_refs, candidate, names)
        guesses.append(Guess(node, refs, tag))


def match_functions(segments, patterns, guesses, position_to_ea, names):
    """
    Match function fingerpints agains current IDA analysis state
    """

    # enumerate and match functions
    explored = []
    count = ida.get_func_qty()
    print('  functions  ')
    for n in progress(range(count)):
        # get function info
        function = ida.getn_func(n)
        fn_start = function.start_ea
        fn_end = function.end_ea
        explored.append((fn_start, fn_end))
        if not is_address_fingerprintable(fn_start, segments):
            continue

        ida.show_auto(fn_start, ida.AU_USED)

        # signature match
        size = min(fn_end - fn_start, signature_size)
        signature_bytes = ida.get_bytes(fn_start, size)
        snodes = None
        candidates = []
        for s in range(size):
            candidates, snodes = patterns.match(signature_bytes[s], snodes)
            if not snodes:
                candidates = []
                break
        candidates = [c for c in candidates if c['type'] == 'function']
        if not candidates:
            continue

        # match candidates function trace
        match_function_candidates(fn_start, fn_end, candidates, guesses, position_to_ea, names)
    ida.show_auto(0, ida.AU_NONE)

    return explored


def match_data_candidates(start, data_bytes, candidates, guesses):
    """
    Match data candidates on given binary location
    """

    if all(byte == 0xff for byte in data_bytes):
        return

    fingerprint = fnv_start
    for n, byte in enumerate(data_bytes):
        fingerprint = fnv_hash(fingerprint, byte)
    candidates = [c for c in candidates if c['fingerprint'] == fingerprint]
    if not candidates:
        return

    # todo remember candidates behind limit
    candidates = candidates[:max_candidates]

    # update guesses
    for candidate in candidates:
        node = GuessNode((start, start + candidate['size']), candidate['name'])
        tag = guess_strong if candidate['strong'] else guess_weak
        guesses.append(Guess(node, [], tag))


def match_data(segments, patterns, guesses, names):
    """
    Match data against current IDA analysis state
    """

    # enumerate and match data
    count = ida.get_nlist_size()
    explored = []
    print('  data  ')
    for n in progress(range(count)):
        # collect information
        data_start = ida.get_nlist_ea(n)
        flags = ida.get_flags(data_start)
        data_size = ida.get_item_size(data_start)
        explored.append((data_start, data_start + data_size))

        if not ida.is_data(flags):
            continue
        if not is_address_fingerprintable(data_start, segments):
            continue

        ida.show_auto(data_start, ida.AU_USED)
        data_bytes = ida.get_bytes(data_start, data_size)

        # signature match
        snodes = None
        candidates = []
        for n in range(min(data_size, signature_size)):
            candidates, snodes = patterns.match(data_bytes[n], snodes)
            if not snodes:
                candidates = []
                break
        candidates = [c for c in candidates if c['type'] == 'data']
        if not candidates:
            continue

        # fingerprint match
        match_data_candidates(data_start, data_bytes, candidates, guesses)
    ida.show_auto(0, ida.AU_NONE)

    return explored


def verify_matches(matches, annotations):
    """
    Compute matches score against annotations
    """

    # remove unknowns
    stripped_matches = set(ea_name for ea_name in matches if isinstance(ea_name[1], str))

    # compute metrics
    fps = sorted(stripped_matches - annotations)
    tp = len(stripped_matches & annotations)
    fp = len(fps)
    fn = len(annotations - stripped_matches)
    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    f1 = 2 * precision * recall / ((precision + recall) if precision + recall > 0 else 0)

    print('annotations')

    # show false positives
    for ea, name in fps:
        print('  fp  {}, {}'.format(hex(ea[0]), name))

    # show metrics
    print('  precision  {:.3f}'.format(precision))
    print('  recall  {:.3f}'.format(recall))
    print('  f1 score  {:.3f}'.format(f1))


def match_evidence(guesses, names):
    """
    Match items from fingerprint evidence
    """

    print('resolving guesses')
    print('  guesses  {}'.format(len(guesses)))

    # todo strip guessnode type

    # scores for unambiguous subgraph nodes
    score_weak = 1
    score_strong = 2
    score_threshold = 3

    # node to guess index
    node_to_guess = {guess.node: guess for guess in guesses}

    # find consistent subgraphs
    seen = set()
    consistent_nodes = {}
    consistent_subgraphs = []
    for guess in progress(guesses):
        node = guess.node
        if node in seen:
            continue

        ida.show_auto(node.ea[0], ida.AU_USED)

        # create subgraph
        score = 0
        subgraph = set()
        stack = set([node])
        while stack:
            node = stack.pop()
            subgraph.add(node)

            node_guess = node_to_guess.get(node)
            if node_guess is None:
                continue

            next_subgraph_score = consistent_nodes.get(node)
            if next_subgraph_score is not None:
                next_subgraph, next_score = next_subgraph_score
                score += next_score
                subgraph.update(next_subgraph)
                continue

            score += score_strong if node_guess.tag == guess_strong else score_weak
            seen.add(node)
            for ref in node_guess.refs:
                if ref not in subgraph:
                    stack.add(ref)

        # check subgraph name consistency
        subgraph_names = set(node.name for node in subgraph)
        if len(subgraph_names) != len(subgraph):
            continue

        # check subgraph range consistency
        subgraph_ranges = IntervalTree((*node.ea, None) for node in subgraph)
        if any(len(subgraph_ranges.find(*node.ea)) != 1 for node in subgraph):
            continue

        # save consistent nodes with subgraph
        for node in subgraph:
            consistent_nodes[node] = None
        consistent_nodes[guess.node] = (subgraph, score)
        consistent_subgraphs.append((subgraph, score))

    guesses = [node_to_guess[node] for node in consistent_nodes if node in node_to_guess]
    consistent_subgraphs.sort(key=lambda x: -x[1])

    # rescore
    """
    node_scores = {}
    for subgraph, score in consistent_subgraphs:
        for node in subgraph:
            node_scores[node] = node_scores.get(node, 0) + score

    rescored_subgraphs = []
    for subgraph, score in consistent_subgraphs:
        rescored_subgraphs.append((subgraph, sum(node_scores[node] for node in subgraph)))
    consistent_subgraphs = rescored_subgraphs
    """

    # iteratively create match list
    matches = set()
    for subgraph, score in progress(consistent_subgraphs):
        ida.show_auto(next(iter(subgraph)).ea[0], ida.AU_USED)

        # pick unexplored subgraph
        if score < score_threshold:
            break
        unexplored_subgraph = subgraph - matches
        if not unexplored_subgraph:
            continue

        matched_names = set(node.name for node in unexplored_subgraph)
        matched_ranges = IntervalTree((*node.ea, None) for node in unexplored_subgraph)

        # check consistency with matches
        if all(match in unexplored_subgraph or (match.name not in matched_names and not matched_ranges.find(*match.ea)) for match in matches):
            matches.update(unexplored_subgraph)

    # gather inconsistent nodes
    matched_ranges = IntervalTree((*ea, None) for ea, name in matches)
    matched_names = {name for ea, name in matches}
    inconsistent_nodes = set()
    for guess in progress(guesses):
        node = guess.node

        ida.show_auto(node.ea[0], ida.AU_USED)

        if node not in matches and (node.name in matched_names or matched_ranges.find(*node.ea)):
            inconsistent_nodes.add(node)
            continue

        if any(ref not in matches and (ref.name in matched_names or matched_ranges.find(*ref.ea)) for ref in guess.refs):
            inconsistent_nodes.add(node)

    # todo verify expansion
    # expand inconsistent nodes with back reference search
    while progress(True):
        new_guesses = []
        for guess in guesses:
            if guess.node in inconsistent_nodes:
                continue

            ida.show_auto(guess.node.ea[0], ida.AU_USED)

            if any(ref in inconsistent_nodes for ref in guess.refs):
                inconsistent_nodes.add(guess.node)
            else:
                new_guesses.append(guess)
        if len(new_guesses) == len(guesses):
            break
        guesses = new_guesses

    ida.show_auto(0, ida.AU_NONE)

    # compile guesses
    guesses = [guess for guess in guesses if guess.node not in matches]

    # print results
    data_count = 0
    function_count = 0
    for ea, name in matches:
        node = names.get(name)
        if node is not None and node['type'] == 'function':
            function_count +=  1
        elif node is not None and node['type'] == 'data':
            data_count +=  1

    print('  function matches  {}'.format(function_count))
    print('  data matches  {}'.format(data_count))
    print('  unresolved guesses  {}'.format(len(guesses)))

    return matches, guesses


def match_unknown(segments, explored, patterns, guesses, position_to_ea, names):
    """
    Match unknown areas
    """

    # build interval tree for explored areas
    explored_intervals = IntervalTree([(start, end, end) for start, end in explored if end - start >= signature_size])

    # enumerate segments
    for name, segment_start, segment_end, segment_type in list_segments():
        print('  segment {}  '.format(name))
        segment_size = segment_end - segment_start
        segment_bytes = ida.get_bytes(segment_start, segment_size)

        # collect candidates for each byte
        n = 0
        while n < segment_size:
            # skip already explored areas
            interval_end = explored_intervals.find(segment_start + n)
            if interval_end:
                n = interval_end[-1] - segment_start
                continue

            # find candidates inside moving window
            snodes = None
            start = segment_start + n
            ida.show_auto(start, ida.AU_USED)
            for s in range(n, min(n + signature_size, segment_size)):
                candidates, snodes = patterns.match(segment_bytes[s], snodes)
                if not snodes:
                    break

                fn_candidates = [c for c in candidates if c['type'] == 'function']
                data_candidates = [c for c in candidates if c['type'] == 'data']

                # match functions
                if fn_candidates:
                    match_function_candidates(start, segment_end, fn_candidates, guesses, position_to_ea, names)

                # match data
                if data_candidates:
                    sizes = {}
                    for candidate in candidates:
                        guess = sizes.setdefault(candidate['size'], [])
                        guess.append(candidate)

                    for size, candidates in sizes.items():
                        if start + size >= segment_end:
                            continue
                        match_data_candidates(start, segment_bytes[start:start + size], candidates, guesses)

            n += 1
        ida.show_auto(0, ida.AU_NONE)


def matches_apply(matched_eas, names, imported_types, explored, position_to_ea):
    """
    Aplies matched items
    """

    print('applying matches  ')
    applied_functions = 0
    applied_data = 0
    applied_comments = 0
    applied_names = {}
    for n, (ea, name) in progress(enumerate(matched_eas.items())):
        if name not in names:
            continue

        ida.show_auto(ea, ida.AU_LIBF)

        # name
        node = names[name]
        if node['user']:
            sn_flags = ida.SN_NOCHECK | ida.SN_FORCE
            if node['public']:
                sn_flags |= ida.SN_PUBLIC
            else:
                sn_flags |= ida.SN_NON_PUBLIC
            if node['weak']:
                sn_flags |= ida.SN_WEAK
            else:
                sn_flags |= ida.SN_NON_WEAK
            ida.set_name(ea, name, sn_flags)

        # comments, flags
        if node['type'] == 'data':
            for pos, comment in node['cmt'].items():
                ida.set_cmt(ea + pos, comment, False)
                applied_comments += 1
            for pos, comment in node['cmt_rep'].items():
                ida.set_cmt(ea + pos, comment, True)
                applied_comments += 1

            explored.append((ea, ea + node['size']))
            applied_names[ea] = name
            applied_data += 1
        elif node['type'] == 'function':
            function = ida.get_func(ea)
            if function is None:
                ida.auto_make_proc(ea)
                ida.auto_wait()
            function = ida.get_func(ea)
            if function is None:
                continue

            function.flags = node['flags']
            if node['cmt'] is not None:
                ida.set_func_cmt(function, node['cmt'], False)
                applied_comments += 1
            if node['cmt_rep'] is not None:
                ida.set_func_cmt(function, node['cmt_rep'], True)
                applied_comments += 1

            for pos, comments in node['code_cmt'].items():
                if (name, ea) in position_to_ea:
                    ida.set_cmt(position_to_ea[(name, ea)][pos], '\n'.join(comments), False)
                    applied_comments += 1
            for pos, comments in node['code_cmt_rep'].items():
                if (name, ea) in position_to_ea:
                    ida.set_cmt(position_to_ea[(name, ea)][pos], '\n'.join(comments), True)
                    applied_comments += 1

            explored.append((ea, function.end_ea))
            applied_names[ea] = name
            applied_functions += 1

        # type
        if node['tdecl'] is not None:
            if node['type'] == 'function':
                tdecl_escaped = insert_function_name(escape_type(node['tdecl']), 'placeholder')
            else:
                tdecl_escaped = escape_type(node['tdecl'])

            tinfo = ida.tinfo_t()
            if ida.parse_decl(tinfo, None, tdecl_escaped, ida.PT_SIL) is not None:
                ida.set_tinfo(ea, tinfo)

    ida.show_auto(0, ida.AU_NONE)
    import_types_rename(imported_types)

    return applied_names, (applied_functions, applied_data, applied_comments)


def save_matches(filename, matches):
    """
    Save matches to a json file
    """

    print('writing matches into  {}'.format(filename))

    with open(filename, 'wt', encoding='utf8') as fd:
        json_guesses = {hex(start): name for (start, end), name in matches}
        json.dump(json_guesses, fd, indent=2, sort_keys=True)

def save_guesses(filename, guesses):
    """
    Save guesses into json file
    """
    print('writing guesses into  {}'.format(filename))

    json_guesses = {}
    for guess in guesses:
        name = guess.node.name if isinstance(guess.node.name, str) else 'unknown_{}'.format(guess.node.name[0])
        ea = guess.node.ea[0]
        names = json_guesses.setdefault(ea, set())
        names.add(name)
    json_guesses = {hex(ea): list(names) for ea, names in json_guesses.items()}

    with open(filename, 'wt', encoding='utf8') as fd:
        json.dump(json_guesses, fd, indent=2, sort_keys=True)


def match(fingerdb_path, annotations_path, apply_matches):
    """
    Matches db against fingerprints
    """

    # unpickle fingerprints
    print('loading fingerprints from  {}'.format(fingerdb_path))
    db = load_fdb(fingerdb_path)
    version = db.get('version', -1)
    if not isinstance(version, (int, float)) or version < 0:
        raise OperationFailed('you have loaded old version of database, please recreate the database')
    nodes = db['nodes']
    patterns = db['patterns']
    patterns_unknown = db['patterns_unknown']
    names = db['names']
    types = db['types']

    print('  fingerprints  {}'.format(len(nodes)))

    # match fingerprints
    print('matching')
    guesses = []
    position_to_ea = {}
    explored = []
    segments = list_segments()
    explored.extend(match_functions(segments, patterns, guesses, position_to_ea, names))
    explored.extend(match_data(segments, patterns, guesses, names))
    match_unknown(segments, explored, patterns_unknown, guesses, position_to_ea, names)

    # resolve matches based on collected evidence
    matches, guesses = match_evidence(guesses, names)

    # verify matches
    if annotations_path:
        annotations = load_annotations(annotations_path)
        verify_matches(matches, annotations)

    # apply matches
    if apply_matches:
        matched_eas = {start: name for (start, end), name in matches}
        matched_names = {name: start for (start, end), name in matches}

        # import types
        if any(name in names and names[name]['type'] == 'function' for name in matched_names):
            imported_types = import_types(types)
        else:
            print('did not match any functions, done\n')
            return

        # apply names
        applied, counts = matches_apply(matched_eas, names, imported_types, explored, position_to_ea)
        fns_first, data_first, cmts_first = counts

        # save matches and guesses
        idb = ida.get_path(ida.PATH_TYPE_IDB)
        save_matches('{}.fingermatch_matches.json'.format(idb), matches)
        save_guesses('{}.fingermatch_guesses.json'.format(idb), guesses)

        print('results')
        print('  imported types  {}'.format(len(imported_types)))
        print('  applied functions  {}'.format(fns_first))
        print('  applied data  {}'.format(data_first))
        print('  applied comments  {}'.format(cmts_first))
        print('done\n')

    return matches


def fingermatch_merge(filenames, output_name, exclusions=None):
    """
    Merge several fingematch databases into one
    filenames: list of fingerprint databases to merge
    output_name: name of output dadtabase
    exclusions: list of regexps, names matching any of these will be excluded
    """

    raise NotImplementedError('Merging databases is not implemented yet')


def fingermatch_collect(fingerdb_path, annotations_path=None):
    """
    Collect functions, data, types and comments and save them into database

    fingerdb_path: when provided create fingerprint database to save collected items to
    annotations_path: when provided create a jsonl file with annotations

    Return list of collected nodes, list of collected types
    """

    if fingerdb_path is None and annotations_path is None:
        raise ValueError('At least one of fingerdb_path and annotations_path must be provided')

    ida.show_wait_box('collecting fingerprints')
    try:
        return collect(fingerdb_path, annotations_path)
    except UserInterrupt:
        print('\nuser interrupted collecting fingerprints\n')
    except OperationFailed as exception:
        print(exception)
    finally:
        ida.hide_wait_box()


def fingermatch_match(fingerdb_path, annotations_path=None, apply_matches=True):
    """
    Load fingerprints from a database and match them to current analysed binary

    fingerdb_path: path to fingerprint database to load fingerprints from
    annotations_path: when provided compute how successful matching was against annotations
    apply_matches: when True apply matches to open analysis

    Return set of found matches GuessNode, list of remaining guesses Guess
    """

    ida.show_wait_box('matching fingerprints')
    try:
        return match(fingerdb_path, annotations_path, apply_matches)
    except UserInterrupt:
        print('\nuser interrupted matching fingerprints\n')
    except OperationFailed as exception:
        print(exception)
    finally:
        ida.hide_wait_box()


def publish_api(names):
    """
    Make API function available to IDA namespae
    """

    module = sys.modules['__main__']
    sys.modules['fingermatch'] = importlib.import_module('fingermatch', None)
    for name, var in names:
        setattr(module, name, var)


def remove_api(names):
    """
    Remove API from publick namespace
    """

    module = sys.modules['__main__']
    for name in names:
        if hasattr(module, name):
            delattr(module, name)

    if 'fingermatch' in sys.modules:
        del sys.modules['fingermatch']


class FingerprintAction(ida.action_handler_t):
    """
    Handles fingerprinting action
    """

    def __init__(self):
        ida.action_handler_t.__init__(self)

    def activate(self, ctx):
        """
        Run fingerprinting
        """

        fingerdb_path = ida.ask_file(True, '*.fdb', 'Database to save fingerprints')
        if fingerdb_path is not None:
            fingermatch_collect(fingerdb_path)

        return 1

    def update(self, ctx):
        """
        Set action always enabled
        """

        return ida.AST_ENABLE_ALWAYS


class MatchAction(ida.action_handler_t):
    """
    Handles match action
    """

    def __init__(self):
        ida.action_handler_t.__init__(self)


    def activate(self, ctx):
        """
        Run matching
        """

        fingerdb_path = ida.ask_file(False, '*.fdb', 'Open fingerprints database')
        if fingerdb_path is not None:
            fingermatch_match(fingerdb_path)

        return 1


    def update(self, ctx):
        """
        Set action always enabled
        """

        return ida.AST_ENABLE_ALWAYS


class FingerMatch(ida.plugin_t):
    """
    Wraps fingerprinting functions into IDA plugin
    """

    flags = 0
    comment = 'Plugin collects function and data fingerprints, types and comments into a file to be matched later for analysis other binaries.'
    help = 'Use View -> collect fingerprints to collect available information and View -> match fingerprints to find colected fingerprints in a given binary.'
    wanted_name = 'FingerMatch'
    wanted_hotkey = ''

    def init(self):
        """
        Initialize plugin, add menu items to IDA UI
        """

        if sys.version_info[0] <= 2:
            print('FingerMatch supports Python 3+, you are using older version.')
            return ida.PLUGIN_SKIP

        action_collect = ida.action_desc_t(
            'fingerprints_collect',
            'Collect fingerprints',
            FingerprintAction(),
            '',
            'Collect functions, data, types and comments from open db and save them into a file',
            39)
        action_match = ida.action_desc_t(
            'fingerprints_match',
            'Match fingerprints',
            MatchAction(),
            '',
            'Search for fingerprints from a file in current db',
            154)
        ida.register_action(action_collect)
        ida.register_action(action_match)
        ida.attach_action_to_menu('View/Fingerprints', 'fingerprints_collect', ida.SETMENU_APP)
        ida.attach_action_to_menu('View/Fingerprints', 'fingerprints_match', ida.SETMENU_APP)

        publish_api([
            ('fingermatch_collect', fingermatch_collect),
            ('fingermatch_match', fingermatch_match),
            ('fingermatch_merge', fingermatch_merge)])

        return ida.PLUGIN_KEEP


    def term(self):
        """
        Terminate plugin
        """

        ida.detach_action_from_menu('View', 'fingerprints_collect')
        ida.detach_action_from_menu('View', 'fingerprints_match')
        ida.unregister_action('fingerprints_collect')
        ida.unregister_action('fingerprints_match')

        remove_api(['fingermatch_collect', 'fingermatch_match', 'fingermatch_merge'])


    def run(self, arg):
        """
        Run plugin, show help
        """

        ida.info('FingerMatch plugin\n\nTo collect fingerprints go to View -> Collect fingerprints.\nTo match stored fingerprints go to View -> Match fingerprints.')


def PLUGIN_ENTRY():
    """
    FingerMatch IDA plugin entrypoint
    """

    return FingerMatch()


def selftest_intervals():
    """
    testing intervals
    """

    intervals = [
        (-20, -10, None),
        (0, 10, 'a'),
        (10, 20, 'b'),
        (21, 30, 'c'),
        (5, 25, 'abc'),
        (21, 30, 'cc'),
    ]

    tree = IntervalTree(intervals)
    assert tree.find(-1000) == []
    assert tree.find(1000) == []
    assert tree.find(0) == ['a']
    assert tree.find(9) == ['a', 'abc']
    assert tree.find(10) == ['abc', 'b']
    assert tree.find(20) == ['abc']

    assert tree.find(-1100, -1000) == []
    assert tree.find(1000, 1100) == []
    assert tree.find(-5, 35) == ['a', 'abc', 'b', 'c', 'cc']
    assert tree.find(0, 1) == ['a']
    assert tree.find(1, 5) == ['a']
    assert tree.find(1, 6) == ['a', 'abc']
    assert tree.find(10, 25) == ['abc', 'b', 'c', 'cc']

    assert tree.find(-20, -10) == [None]


def selftest_pattern_trie():
    """
    testing pattern trie
    """

    trie = PatternTrie()
    trie.add([0, 1, 2], 'a')
    trie.add([0, 1, 3], 'b')
    trie.add([0, 2], 'c')
    trie.add([0, None, 3], 'd')
    trie.add([1, 3], 'e')
    trie.add([1], 'e')

    results, nodes = trie.match(0)
    assert results == []
    results, nodes = trie.match(1, nodes)
    assert results == []
    results, nodes = trie.match(3, nodes)
    assert set(results) == {'b', 'd'}
    results, nodes = trie.match(0, nodes)
    assert results == [] and nodes == []

    results, nodes = trie.match(1)
    assert set(results) == {'e'}
    results, nodes = trie.match(1, nodes)
    assert results == [] and nodes == []


def selftest_all():
    """
    Run selftest
    """

    print('running fingermatch selftests')
    for fn in [
        selftest_intervals,
        selftest_pattern_trie,
        ]:
        print('  {}'.format(fn.__doc__.strip()))
        fn()


# run selftest if script is not activated as a plugin
if __name__ == '__main__':
    selftest_all()
