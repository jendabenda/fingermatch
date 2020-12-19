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
 * matched items are written into csv file
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
import csv
import json
import bisect
import math
import time
import importlib
import gzip
import io
import re
import pickle

import idaapi as ida


signature_size = 32  # length of function/data signature
strong_match_fn_size = 16  # minimum instructions to consider function a strong match
strong_match_data_size = 10  # minimum size in bytes to consider data a strong match
useless_bytes = set([0x00, 0x01, 0x02, 0x04, 0x08, 0x7f, 0x80, 0xff])  # useless bytes for data fingerprinting
useful_bytes_count = 3  # minimum number of useful bytes for data fingerprinting


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


class ProgressBar:
    """
    Text UI progress bar
    """

    def __init__(self, text):
        self.bars = 0
        self.max_bars = 50
        self.char = '='
        self.start = time.monotonic()

        sys.stdout.write(text)
        #sys.stdout.write('[')


    def update(self, value):
        """
        Update progress bar
        """

        bars = int(max(0, min(value, 1)) * self.max_bars)
        new_bars = max(0, bars - self.bars)
        self.bars = bars
        if new_bars > 0:
            #sys.stdout.write(self.char * new_bars)
            pass

        if ida.user_cancelled():
            raise UserInterrupt()


    def finish(self):
        """
        Finish progres `bar progression
        """

        self.update(1)
        #sys.stdout.write(']  took {:.2f}s\n'.format(time.monotonic() - self.start))
        sys.stdout.write('\n')

        if ida.user_cancelled():
            raise UserInterrupt()


class IntervalTree:
    """
    Interval "tree", assuming small ammount of overlaps.
    Finds overlapping intevals and merges them into parent one. One level nesting only.
    """

    def __init__(self, intervals):
        """
        Build interval data structure
        """

        intervals = sorted(intervals, key=lambda x: x[0])

        sequence = []
        starts = []
        if intervals:
            # find overlapping intervals
            overlap = [intervals[0]]
            overlap_end = intervals[0][1]
            for interval in intervals[1:]:
                start, end, data = interval
                if overlap_end > start:
                    overlap_end = max(overlap_end, end)
                    overlap.append(interval)
                else:
                    if len(overlap) == 1:
                        sequence.append((overlap[0][0], overlap[0][1], overlap[0][2], None))
                    else:
                        sequence.append((overlap[0][0], overlap_end, None, overlap))
                    starts.append(overlap[0][0])
                    overlap = [interval]
                    overlap_end = end
            if len(overlap) == 1:
                sequence.append((overlap[0][0], overlap[0][1], overlap[0][2], None))
            else:
                sequence.append((overlap[0][0], overlap_end, None, overlap))
            starts.append(overlap[0][0])

        self.starts = starts
        self.intervals = sequence


    def find(self, point):
        """
        Find first interval containing given point and return interval data
        """

        index = bisect.bisect(self.starts, point) - 1
        if index == -1:
            return None

        start, end, data, overlap = self.intervals[index]
        if point < start or point >= end:
            return None

        if overlap is None:
            return data
        else:
            for start, end, data in overlap:
                if start <= point < end:
                    return data

            return None


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
    progress = ProgressBar('collecting types  ')
    for ordinal in range(1, ordinal_count + 1):
        progress.update(ordinal / (ordinal_count + 1))
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
    progress.finish()

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
    progress = ProgressBar('  functions  ')
    for n in range(count):
        progress.update(n / count)

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
    progress.finish()
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
    progress = ProgressBar('  data  ')
    data = []
    count = ida.get_nlist_size()
    for n in range(count):
        progress.update(n / count)

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
    progress.finish()
    ida.show_auto(0, ida.AU_NONE)

    return data


def ref_to_symbol(ref, node):
    """
    Converts reference to symbolic value
    """

    if node is None:
        return None, None

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
        node = node_intervals.find(ref)
        name, offset = ref_to_symbol(ref, node)
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

    progress = ProgressBar('building matching structures  ')
    node_count = len(nodes)
    patterns = PatternTrie()
    patterns_unknown = PatternTrie()
    for n, node in enumerate(nodes):
        progress.update(n / node_count)
        if node['signature'] is not None:
            patterns.add(node['signature'], node)
            if node['strong']:
                patterns_unknown.add(node['signature'], node)
    progress.finish()

    return patterns, patterns_unknown


def verify_strongness(nodes):
    """
    Verify if strong nodes are unambiguous, possibly removing strong attribute
    """

    progress = ProgressBar('  checking uniqueness  ')
    node_count = len(nodes)
    fingerprints = {}
    for n, node in enumerate(nodes):
        progress.update(n / node_count)
        fprint = node['fingerprint']
        if fprint in fingerprints:
            node['strong'] = False
            fingerprints[fprint]['strong'] = False
        else:
            fingerprints[fprint] = node
    progress.finish()


def collect(filename):
    """
    Create fingerprints for whole db
    """

    print('collecting')
    segments = list_segments()

    # fingerprinting
    nodes = []
    nodes.extend(fingerprint_functions(segments))
    nodes.extend(fingerprint_data_places(segments))
    node_count = len(nodes)

    function_count = 0
    data_count = 0
    for node in nodes:
        if node['type'] == 'function':
            function_count += 1
        elif node['type'] == 'data':
            data_count += 1

    print('  function count  {}'.format(function_count))
    print('  data count  {}'.format(data_count))
    print('postprocessing')

    # resolve references
    node_intervals = IntervalTree([(node['ea'], node['ea'] + node['size'], node) for node in nodes])
    progress = ProgressBar('  resolving references  ')
    unknowns = {}
    reference_count = 0
    for n, node in enumerate(nodes):
        progress.update(n / node_count)
        node['refs'] = resolve_refs(node['refs'], node_intervals, unknowns)
        reference_count += len(node['refs'])
    progress.finish()
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
    print('saving fingerprints to  {}'.format(filename))
    save_fdb(filename, {
        'nodes': nodes,
        'patterns': patterns,
        'patterns_unknown': patterns_unknown,
        'names': names,
        'types': types,
    })

    print('done\n')


def match_refs(match_ea, match_refs, candidates, names):
    """
    Match forward refrences to set of candidates
    """

    # inspect all candidates
    guesses = {}
    for candidate in candidates:
        # enumerate candidate refs
        for mdst, (cpos, cdst, cdst_offset) in zip(match_refs, candidate['refs']):
            cnode = names.get(cdst)
            if cnode is None:
                cname = cdst
                cea = mdst
            elif cnode['type'] == 'data':
                # todo offsets needs to extend guesses with ranges
                if cdst_offset == 0:
                    cname = cnode['name']
                    cea = mdst
                else:
                    #cea = mdst - cdst_offset
                    continue
            elif cnode['type'] == 'function':
                cname = cnode['name']
                cea = mdst
            else:
                assert False, 'unknown node type {}'.cnode['type']

            evidence = guesses.setdefault(cea, {})
            drafts = evidence.setdefault(match_ea, set())
            drafts.add(cname)

    return guesses


def merge_guesses(a, b):
    """
    Merge second guesses into the first ones
    """

    for b_ea, b_evidence in b.items():
        for b_source, b_drafts in b_evidence.items():
            a_evidence = a.setdefault(b_ea, {})
            a_evidence[b_source] = a_evidence.get(b_source, set()) | b_drafts


def match_function_candidates(start, end, candidates, names, guesses, position_to_ea):
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

    # match references
    guesses_from_refs = match_refs(start, trace_refs, candidates, names)

    # update position to ea map
    for candidate in candidates:
        position_to_ea[(candidate['name'], start)] = cposition_to_ea

    # update guesses
    only_candidate = len(candidates) == 1
    for candidate in candidates:
        match_source = 'strong' if only_candidate and candidate['strong'] else 'weak'
        evidence = guesses.setdefault(start, {})
        drafts = evidence.setdefault(match_source, set())
        drafts.add(candidate['name'])

    # merge guesses from forward refs
    merge_guesses(guesses, guesses_from_refs)


def match_functions(segments, patterns, names, guesses, position_to_ea):
    """
    Match function fingerpints agains current IDA analysis state
    """

    # enumerate and match functions
    explored = []
    count = ida.get_func_qty()
    progress = ProgressBar('  functions  ')
    for n in range(count):
        progress.update(n / count)

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
        for n in range(size):
            candidates, snodes = patterns.match(signature_bytes[n], snodes)
            if not snodes:
                candidates = []
                break
        candidates = [c for c in candidates if c['type'] == 'function']
        if not candidates:
            continue

        # match candidates function trace
        match_function_candidates(fn_start, fn_end, candidates, names, guesses, position_to_ea)
    progress.finish()
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

    # update guesses
    only_candidate = len(candidates) == 1
    for candidate in candidates:
        match_source = 'strong' if only_candidate and candidate['strong'] else 'weak'
        evidence = guesses.setdefault(start, {})
        drafts = evidence.setdefault(match_source, set())
        drafts.add(candidate['name'])


def match_data(segments, patterns, names, guesses):
    """
    Match data against current IDA analysis state
    """

    # enumerate and match data
    count = ida.get_nlist_size()
    explored = []
    progress = ProgressBar('  data  ')
    for n in range(count):
        progress.update(n / count)

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
    progress.finish()
    ida.show_auto(0, ida.AU_NONE)

    return explored


def prune_guesses(guesses, matched_eas, matched_names):
    """
    Prune guesses based on matched evidence
    """

    # prune guesses
    for ea in matched_eas:
        if ea in guesses:
            del guesses[ea]

    # prune evidence drafts by matched items
    matched_names_set = set(matched_names)
    for ea, evidence in guesses.items():
        for source in list(evidence):
            evidence[source] -= matched_names_set
            if not evidence[source]:
                del evidence[source]

    # prune evidence source by matched items
    for ea, evidence in guesses.items():
        strong_sources = set(source for source in evidence if source in matched_eas)
        if strong_sources:
            for source in list(evidence):
                if source not in strong_sources:
                    del evidence[source]

    # prune empty guesses
    for ea in list(guesses):
        if not guesses[ea]:
            del guesses[ea]


def match_evidence(matched_eas, matched_names, guesses, names):
    """
    Match items from evidence fingerprints at given evel
    """

    print('resolving guesses')
    unambiguous_eas = {}
    unambiguous_refs = {}
    while True:
        if ida.user_cancelled():
            raise UserInterrupt()

        # find unambiguous candidates
        added = True
        new_unambiguous_eas = {}
        while added:
            added = False
            for ea, evidence in guesses.items():
                if ea in unambiguous_eas:
                    continue
                drafts = set.intersection(*evidence.values())
                if (len(drafts) == 1 and
                    any(isinstance(source, str) or source in unambiguous_eas for source in evidence)):
                    draft = drafts.pop()
                    if draft not in matched_names:
                        new_unambiguous_eas[ea] = draft
                        unambiguous_eas[ea] = draft
                        added = True

        # find unambiguous references
        for ea in new_unambiguous_eas:
            for source in guesses.get(ea, []):
                if source in unambiguous_eas:
                    refs = unambiguous_refs.setdefault(source, set())
                    refs.add(ea)
                    refs = unambiguous_refs.setdefault(ea, set())
                    refs.add(source)

        # create unambiguous subgraphs
        subgraphs = []
        visited = set()
        for ea in unambiguous_eas:
            if ea in matched_eas:
                continue

            subgraph = set()
            stack = [ea]
            while stack:
                ea = stack.pop()
                if ea in visited:
                    continue

                subgraph.add(ea)
                visited.add(ea)
                if ea in unambiguous_refs:
                    stack.extend(unambiguous_refs[ea])
            if subgraph:
                subgraphs.append(subgraph)

        # score subgraphs
        score_strong = 3
        score_weak = 1
        score_threshold = 3
        score_conflict = -1
        strong_subgraphs = []
        for graph in subgraphs:
            score = 0
            for ea in graph:
                name = unambiguous_eas[ea]
                if name in names and names[name]['strong']:
                    score += score_strong
                else:
                    score += score_weak
            if score >= score_threshold:
                strong_subgraphs.append((score, graph))
        strong_subgraphs.sort(key=lambda score_graph: -score_graph[0])

        # inspect all strong subgraphs, create matches
        new_matched_eas = {}
        new_matched_names = {}
        used_names = set()
        for score, graph in strong_subgraphs:
            # check name conflicts
            conflicts = set()
            for ea in graph:
                name = unambiguous_eas[ea]
                if name in used_names:
                    score += 2 * score_conflict if name in conflicts else score_conflict
                    conflicts.add(name)
                used_names.add(name)

            if score < score_threshold:
                continue

            # add graph to matches
            for ea in graph:
                if ea in matched_eas:
                    continue

                name = unambiguous_eas[ea]
                if name in conflicts:
                    continue

                new_matched_eas[ea] = name
                new_matched_names[name] = ea

        if not new_matched_eas:
            break

        matched_eas.update(new_matched_eas)
        matched_names.update(new_matched_names)

        # prune guesses
        prune_guesses(guesses, new_matched_eas, new_matched_names)

    # print results
    data_count = 0
    function_count = 0
    for ea, name in matched_eas.items():
        node = names.get(name)
        if node is not None and node['type'] == 'function':
            function_count +=  1
        elif node is not None and node['type'] == 'data':
            data_count +=  1

    print('  function matches  {}'.format(function_count))
    print('  data matches  {}'.format(data_count))
    print('  unresolved guesses  {}'.format(len(guesses)))


def match_unknown(segments, explored, patterns, names, guesses, position_to_ea, exclude):
    """
    Match unknown areas
    """

    # build interval tree for explored areas
    explored_intervals = IntervalTree([(start, end, end) for start, end in explored if end - start >= signature_size])

    # enumerate segments
    for name, segment_start, segment_end, segment_type in list_segments():
        progress = ProgressBar('  segment {}  '.format(name))
        segment_size = segment_end - segment_start
        segment_bytes = ida.get_bytes(segment_start, segment_size)

        # collect candidates for each byte
        n = 0
        while n < segment_size:
            progress.update(n / segment_size)

            # skip already explored areas
            interval_end = explored_intervals.find(segment_start + n)
            if interval_end is not None:
                n = interval_end - segment_start
                continue

            # find candidates inside moving window
            snodes = None
            start = segment_start + n
            ida.show_auto(start, ida.AU_USED)
            for s in range(n, min(n + signature_size, segment_size)):
                candidates, snodes = patterns.match(segment_bytes[s], snodes)
                if not snodes:
                    break

                fn_candidates = [c for c in candidates if c['type'] == 'function'
                    if exclude is None or c['name'] not in exclude]
                data_candidates = [c for c in candidates if c['type'] == 'data'
                    if exclude is None or c['name'] not in exclude]

                # match functions
                if fn_candidates:
                    match_function_candidates(start, segment_end, fn_candidates, names, guesses, position_to_ea)

                # match data
                if data_candidates:
                    sizes = {}
                    for candidate in candidates:
                        group = sizes.setdefault(candidate['size'], [])
                        group.append(candidate)

                    for size, candidates in sizes.items():
                        if start + size >= segment_end:
                            continue
                        match_data_candidates(start, segment_bytes[start:start + size], candidates, guesses)

            n += 1
        progress.finish()
        ida.show_auto(0, ida.AU_NONE)


def apply_matches(matched_eas, names, imported_types, explored, position_to_ea):
    """
    Aplies matched items
    """

    progress = ProgressBar('applying matches  ')
    match_count = len(matched_eas)
    applied_functions = 0
    applied_data = 0
    applied_comments = 0
    applied_names = {}
    for n, (ea, name) in enumerate(matched_eas.items()):
        progress.update(n / match_count)
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

    progress.finish()
    ida.show_auto(0, ida.AU_NONE)
    import_types_rename(imported_types)

    return applied_names, (applied_functions, applied_data, applied_comments)


def save_matches(filename, matched_eas, names):
    """
    Save matches to a csv file
    """

    print('writing matches into  {}'.format(filename))

    with open(filename, 'wt', encoding='utf8') as fd:
        writer = csv.writer(fd)
        for ea, name in sorted(matched_eas.items()):
            node = names.get(name)
            if node is not None:
                writer.writerow([hex(ea), node['type'], name])


def save_guesses(filename, guesses, names):
    """
    Save guesses into json file
    """
    print('writing guesses into  {}'.format(filename))

    json_guesses = {}
    for ea, evidence in guesses.items():
        json_evidence = {}
        for source, drafts in evidence.items():
            json_drafts = [draft if draft in names else 'unknown_{}'.format(draft[0]) for draft in drafts]
            json_source = source if isinstance(source, str) else hex(source)
            json_evidence[json_source] = sorted(json_drafts)

        if not json_evidence:
            continue
        json_guesses[hex(ea)] = json_evidence

    with open(filename, 'wt', encoding='utf8') as fd:
        json.dump(json_guesses, fd, indent=2, sort_keys=True)


def match(filename):
    """
    Matches db against fingerprints
    """

    # unpickle fingerprints
    print('loading fingerprints from  {}'.format(filename))
    db = load_fdb(filename)
    nodes = db['nodes']
    patterns = db['patterns']
    patterns_unknown = db['patterns_unknown']
    names = db['names']
    types = db['types']

    print('  fingerprints  {}'.format(len(nodes)))

    # match fingerprints
    print('matching')
    guesses = {}
    position_to_ea = {}
    explored = []
    segments = list_segments()
    explored.extend(match_functions(segments, patterns, names, guesses, position_to_ea))
    explored.extend(match_data(segments, patterns, names, guesses))
    match_unknown(segments, explored, patterns_unknown, names, guesses, position_to_ea, None)

    # resolve matches based on collected evidence
    matched_eas = {}
    matched_names = {}
    match_evidence(matched_eas, matched_names, guesses, names)

    # import types
    if any(name in names and names[name]['type'] == 'function' for name in matched_names):
        imported_types = import_types(types)
    else:
        print('did not match any functions, done\n')
        return

    # apply names
    applied, counts = apply_matches(matched_eas, names, imported_types, explored, position_to_ea)
    fns_first, data_first, cmts_first = counts

    # save matches and guesses
    idb = ida.get_path(ida.PATH_TYPE_IDB)
    save_matches('{}.fingermatch_matches.csv'.format(idb), matched_eas, names)
    save_guesses('{}.fingermatch_guesses.json'.format(idb), guesses, names)

    print('results')
    print('  imported types  {}'.format(len(imported_types)))
    print('  applied functions  {}'.format(fns_first))
    print('  applied data  {}'.format(data_first))
    print('  applied comments  {}'.format(cmts_first))
    print('done\n')


def fingermatch_merge(filenames, output_name, exclusions=None):
    """
    Merge several fingematch databases into one
    filenames: list of fingerprint databases to merge
    output_name: name of output dadtabase
    exclusions: list of regexps, names matching any of these will be excluded
    """

    # todo rewrite for the new fdb format
    print('Not implemented yet')
    """
    if exclusions is None:
        exclusions = []

    # compile exclusions
    re_exclusions = [re.compile(exclusion, re.I) for exclusion in exclusions]

    # load databases
    fdbs = {}
    for filename in filenames:
        print('loading fingerprints from  {}'.format(filename))
        fdbs[filename] = load_fdb(filename)

    names = {}
    nodes = []

    print('merging')

    # find functions conflicts
    name_to_function = {}
    all_functions = 0
    progress = ProgressBar('  functions  ')
    for filename, fdb in fdbs.items():
        for node in fdb['nodes']:
            if node['type'] == 'function':
                if all(rex.search(node['name']) is None for rex in re_exclusions):
                    function = name_to_function.setdefault(node['name'], [])
                    function.append(node)
                all_functions += 1

    # remove ambiguous functions
    unambiguous_functions = []
    progress.update(0.5)
    for name, functions in name_to_function.items():
        if len(functions) == 1:
            unambiguous_functions.append(functions[0])
    progress.finish()

    # find data conflicts
    name_to_data = {}
    all_data = 0
    for filename, fdb in fdbs.items():
        for node in fdb['nodes']:
            if node['type'] == 'data':
                if all(rex.search(node['name']) is None for rex in re_exclusions):
                    data = name_to_data.setdefault(node['name'], [])
                    data.append(node)
                all_data += 1

    # remove ambiguous data
    unambiguous_data = []
    progress = ProgressBar('  data  ')
    for name, data in name_to_data.items():
        if len(data) == 1:
            unambiguous_data.append(data[0])

    # find type conflicts
    name_to_type = {}
    all_types = 0
    progress.update(0.5)
    for filename, fdb in fdbs.items():
        for type in fdb['types']:
            if all(rex.search(type['name']) is None for rex in re_exclusions):
                types = name_to_type.setdefault(type['name'], [])
                types.append(type)
            all_types += 1
    progress.finish()

    # remove ambiguous types
    unambiguous_types = []
    count = len(name_to_type)
    progress = ProgressBar('  types  ')
    for n, (name, types) in enumerate(name_to_type.items()):
        progress.update(n / count)
        tinfos = [type['tinfo'] for type in types]
        if len(set(tinfos)) == 1:
            unambiguous_types.append(types[0])
    progress.finish()

    print('  used functions  {} / {}'.format(len(unambiguous_functions), all_functions))
    print('  used data  {} / {}'.format(len(unambiguous_data), all_data))
    print('  used types  {} / {}'.format(len(unambiguous_types), all_types))

    print('postprocessing')

    # merge functions and data
    for node in unambiguous_functions:
        nodes.append(node)
        names[node['name']] = node
    for node in unambiguous_data:
        nodes.append(node)
        names[node['name']] = node

    # remove unknown references
    unknown_count = 0
    all_ref_count = 0
    node_count = len(nodes)
    progress = ProgressBar('  cleaning references  ')
    for n, node in enumerate(nodes):
        progress.update(n / node_count)
        for pos, refs in node['refs'].items():
            cleaned_refs = []
            for ref in refs:
                name, offset = ref
                if name in names:
                    cleaned_refs.append(ref)
                else:
                    cleaned_refs.append(((unknown_count,), offset))
                    unknown_count += 1
                all_ref_count += 1
            node['refs'][pos] = cleaned_refs
    progress.finish()
    print('  cleaned references  {} / {}'.format(unknown_count, all_ref_count))

    # verify node strongness (must have unique fingerprint)
    verify_strongness(nodes)

    # signature matching
    patterns, patterns_unknown = build_signature_matcher(nodes)

    # pickle fingerprints
    print('saving fingerprints to  {}'.format(output_name))
    save_fdb(output_name, {
        'nodes': nodes,
        'patterns': patterns,
        'patterns_unknown': patterns_unknown,
        'names': names,
        'types': unambiguous_types,
    })
    """


def fingermatch_collect(filename):
    """
    Collect functions, data, types and comments and save them into database
    filename: path to fingerprint database to save collected items to
    """

    ida.show_wait_box('collecting fingerprints')
    try:
        collect(filename)
    except UserInterrupt:
        print('user interrupted collecting fingerprints\n')
    except OperationFailed as exception:
        print(exception)
    finally:
        ida.hide_wait_box()


def fingermatch_match(filename):
    """
    Load fingerprints from a database and match them to current analysed binary
    filname: path to fingerprin database to load fingerprints from
    """

    ida.show_wait_box('matching fingerprints')
    try:
        match(filename)
    except UserInterrupt:
        print('user interrupted matching fingerprints\n')
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

        filename = ida.ask_file(True, '*.fdb', 'Database to save fingerprints')
        if filename is not None:
            fingermatch_collect(filename)

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

        filename = ida.ask_file(False, '*.fdb', 'Open fingerprints database')
        if filename is not None:
            fingermatch_match(filename)

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
