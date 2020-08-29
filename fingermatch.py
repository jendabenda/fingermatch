"""
FingerMatch

IDA plugin for collecting functions, data, types and comments from analysed binaries
and fuzzy matching them in another binaries.

autor: Jan Prochazka
licence: none, public domain
home: https://github.com/jendabenda/fingermatch


Use for
 * fingerprinting libraries and then matching them in binaries you want to anlayze to save work
   focusing only on unseen and interesting parts
 * resuming analysis when new version of previously analyzed binary is out, so you don't need to
   reverse engineer everything from "scratch"
 * anything what fits


UI
 * menu View -> Collect fingerprints - collects fingerprints and save them into filename
 * menu View -> Match fingerprints - loads fingerprints from filename and match them against
   current binary


Public Python API
 * available to IDA public namespace
 * fingermatch_collect(filename) - collects fingerprints and save them into filename
 * fingermatch_match(filename) - loads fingerprints from filename and match them against current binary
 * fingermatch_merge(filenames, output_name, exclusions) - merges databases in filenames into
 * using Python API is slow, despite running the same code, IDA developers know the answer


Libraries workflow
 * compile library with debugging symbols (\Z7 or \Zi switch with msvc)
 * autoanalyze binary with IDA
 * collect fingerprints with FingerMatch
 * match fingerprints whenever you want

Resumption workflow
 * open binary, analyze it
 * collect fingerprints with FingerMatch
 * when new version is out, open new version
 * match saved fingerprints


Collection process
 * functions - function traces and function referencees
 * data - hashes and data references
 * types
 * comments
 * all metadata of above
 * save to FingerMatch database


Matching process
 * load fingerprints from FingerMatch database
 * function traces and data hashes are matched as candidates
 * graph of guesses is created from candidates and references between them
 * unambigous candidates for functions and data locations are resolved
 * names, types and comments are applied to matched items


Merging process
 * several fingerprint databases can be merged into one
 * duplicities are automatically resolved


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
match the same function, but the function can have shuffled basic blocks, different
register allocation and instruction scheduling within their basic block. Also matching
should be fast indeed, designed for fail fast strategy and efficient exploration of unknown
areas. Basically trace is series of hashes with references. One example is

trace = [(12, 0xaf840b37c19a863, 2, 'eeei', True, 0), ..., ...]
external_crefs = [...]
external_drefs = [...]

Above example is a function consiting of 3 control flow blocks.
The first one has 12 instructions, their cumulative (and commutative) hash
is 0xaf840b37c19a863, there are 2 external data references, 3 external code
references and one internal code reference ('eeei'). Internal references are
immediately pushed onto matcher stack. True means that matcher should explore
instructions after the last one (last instruction is likely conditional
branch) and the last 0 informs matcher to not remove anyting from matcher stack.
For details see fingerprint_function and match_function_candidates.


Todo
 * Aho-Corasic style pattern trie links for faster unknown bytes matching
 * data reference linking
 * smarter database merging strategy
"""

from __future__ import division
from __future__ import print_function

import sys
if sys.version_info[0] == 2:
    import cPickle as pickle
else:
    import pickle
import csv
import json
import bisect
import math
import time
import importlib
import gzip
import io
import re

import idaapi as ida
import idc


signature_size = 32  # length of signature
strong_match_fn_size = 16  # minimum instructions to consider function strong match
strong_match_data_size = 16  # minimum size in bytes to consider data strong match
useless_bytes = set(b'\x00 \x01 \x02 \x04 \x08 \x7f \x80 \xff'.split())  # useless bytes for data fingerprinting
useful_bytes_count = 3  # minimum number of useful bytes for data fingerprinting


class UserInterrupt(Exception):
    """
    Thrown when user cancels running operation
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
        self.start = time.time()

        sys.stdout.write(text)
        sys.stdout.write('[')


    def update(self, value):
        """
        Update progress bar
        """

        bars = int(max(0, min(value, 1)) * self.max_bars)
        new_bars = max(0, bars - self.bars)
        self.bars = bars
        if new_bars > 0:
            sys.stdout.write(self.char * new_bars)

        if ida.user_cancelled():
            raise UserInterrupt()


    def finish(self):
        """
        Finish progres `bar progression
        """

        self.update(1)
        sys.stdout.write(']  took {:.2f}s\n'.format(time.time() - self.start))

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

"""
import random
iters = 1000
iv = []
for n in range(iters):
    s = random.randint(0, 1000000)
    iv.append((s, s + random.randint(1, 100), s))
st = time.time()
it = IntervalTree(iv)
print(time.time() - st)
ss = [random.randint(0, 1000000) for n in range(iters)]
st = time.time()
for s in ss:
    a = it.find(s)
print(time.time() - st)
1/0
"""

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


"""
pt = PatternTrie()
pt.add([0, 6, 9], 'a')
pt.add([0, 6, 9, 1], 'b')
pt.add([1, None, 3], 'c')
pt.add([1, 4, 3], 'd')
data, nodes = pt.match(1)
data, nodes = pt.match(4, nodes)
data, nodes = pt.match(3, nodes)
print(data, nodes)
1/0
"""


fnv_start = 0xcbf29ce484222325
def fnv_hash(hash, num):
    """
    Compute FNV1a hash
    """

    return ((hash ^ num) * 0x100000001b3) & 0xffffffffffffffff


def argsort(sequence):
    """
    Sort sequence indices
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
    Test if segment is usable for fingerprinting
    """

    return any(1 for name, start, end, type in segments if start <= ea < end)


def collect_types():
    """
    Return types used for given nodes
    """

    types = []
    ordinal_count = ida.get_ordinal_qty(None)
    progress = ProgressBar('collecting types\t\t')
    for ordinal in range(1, ordinal_count + 1):
        progress.update(ordinal / (ordinal_count + 1))
        tinfo = ida.get_numbered_type(None, ordinal)
        if tinfo is None:
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
                'tinfo': tinfo,
                'cmt': ida.get_struc_cmt(sid, False),
                'cmt_rep': ida.get_struc_cmt(sid, True),
                'members': members,
                'sync': ida.is_autosync(name, tinfo[0]),
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
                'tinfo': tinfo,
                'cmt': ida.get_enum_cmt(enum, False),
                'cmt_rep': ida.get_enum_cmt(enum, True),
                'members': members,
                'sync': ida.is_autosync(name, tinfo[0]),
            })
        else:
            # plain types
            types.append({
                'name': name,
                'type': 'type',
                'tinfo': tinfo,
                'sync': ida.is_autosync(name, tinfo[0]),
            })
    progress.finish()

    return types


def import_types(types):
    """
    Import types from definitions
    """

    type_count = len(types)
    ordinal_count = ida.get_ordinal_qty(None)

    # collect existing types
    existing_names = set()
    for ordinal in range(ordinal_count):
        existing_names.add(ida.get_numbered_type_name(None, ordinal))

    # collect names to import
    import_names = set()
    for type_dict in types:
        import_names.add(type_dict['name'])

    # import
    import_names = import_names - existing_names
    ordinal_base = ida.alloc_type_ordinals(None, len(import_names))
    ordinal = 0
    errors = []
    imported_count = 0
    progress = ProgressBar('importing types\t\t')
    for n, type_dict in enumerate(types):
        progress.update(n / type_count)
        name = type_dict['name']
        tinfo = type_dict['tinfo']
        type = type_dict['type']
        sync = type_dict['sync']
        if name in import_names:
            result = ida.set_numbered_type(None, ordinal_base + ordinal, 0, name, *tinfo)
            if result == ida.TERR_OK:
                if sync:
                    ida.import_type(None, -1, name, ida.IMPTYPE_OVERRIDE)
                if type == 'enum':
                    # apply enum comments
                    enum = ida.get_enum(name)
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
                    enum = ida.get_enum(name)
                    if enum is not None:
                        ida.set_enum_cmt(enum, type_dict['cmt'], False)
                        ida.set_enum_cmt(enum, type_dict['cmt_rep'], True)

                        # apply bitfield member comments
                        for member in type_dict['members']:
                            ida.set_bmask_cmt(enum, member['bmask'], member['cmt'], False)
                            ida.set_bmask_cmt(enum, member['bmask'], member['cmt_rep'], True)
                elif type == 'struct':
                    # apply struct comments
                    sid = ida.get_struc_id(name)
                    struct = ida.get_struc(sid)
                    if struct is not None:
                        ida.set_struc_cmt(sid, type_dict['cmt'], False)
                        ida.set_struc_cmt(sid, type_dict['cmt_rep'], True)

                        # apply struct member comments
                        for m, member in zip(range(struct.memqty), type_dict['members']):
                            mptr = struct.get_member(m)
                            ida.set_member_cmt(mptr, member['cmt'], False)
                            ida.set_member_cmt(mptr, member['cmt_rep'], True)

                imported_count += 1
            else:
                errors.append(name)

            ordinal += 1
    progress.finish()

    if errors:
        print('  could not import')
        for name in errors:
            print('    {}'.format(name))

    return imported_count


def fingerprint_instruction(instruction):
    """
    Return fingerprint of an instruction
    """

    crefs = []
    drefs = []
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
            instruction_hash = fnv_hash(instruction_hash, 0)

        if operand.type == ida.o_mem:
            drefs.append((n, operand.addr))
        elif otype == ida.o_imm:
            if ida.getseg(operand.value):
                drefs.append((n, operand.value))
        elif operand.type == ida.o_near or operand.type == ida.o_far:
            crefs.append((n, operand.addr))

    return instruction_hash, crefs, drefs


def fingerprint_function(fn_start, fn_end):
    """
    Compute function trace
    """

    # function trace compilation
    comments = {}
    comments_rep = {}
    trace = []
    trace_refs = {}
    trace_block_count = 0
    trace_instruction_count = 0
    blocks = []
    block_start = None
    block_end = None
    block_next = None
    block_crefs = []
    block_dref_count = 0
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
                    trace[-1] = (prev[0], prev[1], prev[2], prev[3], prev[4], prev[5] + block_stack_pops)
                trace.append((
                    block_instruction_count,
                    block_hash,
                    block_dref_count,
                    ''.join(block_crefs),
                    block_next,
                    0))
                trace_block_count += 1
                blocks.append((block_start, block_end))
                block_start = None
                block_end = None
                block_next = None
                block_crefs = []
                block_dref_count = 0
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
            continue
        next_ea = ea + size
        block_end = next_ea

        # fingerprint instruction
        instruction_hash, crefs, drefs = fingerprint_instruction(instruction)
        block_hash = (block_hash + instruction_hash) & 0xffffffffffffffff
        position = (trace_block_count, instruction_hash)
        trace_instruction_count += 1
        block_instruction_count += 1
        block_next = ida.is_flow(ida.get_flags(next_ea))

        # add drefs to trace
        for n, ref in drefs:
            refs = trace_refs.setdefault((trace_block_count, instruction_hash, 'd', n), [])
            refs.append(ref)
            block_dref_count += 1

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
        for n, ref in crefs:
            if fn_start <= ref < fn_end:
                block_crefs.append('i')
                internal_crefs.append((ref, False))
            else:
                block_crefs.append('e')
                refs = trace_refs.setdefault((trace_block_count, instruction_hash, 'c', n), [])
                refs.append(ref)

        stack.extend(internal_crefs)
        if block_next:
            stack.append((next_ea, len(internal_crefs) == 0))

    # append trace
    if trace:
        prev = trace[-1]
        trace[-1] = (prev[0], prev[1], prev[2], prev[3], prev[4], prev[5] + block_stack_pops)
    if block_instruction_count:
        trace.append((
            block_instruction_count,
            block_hash,
            block_dref_count,
            ''.join(block_crefs),
            False,
            0))

    return tuple(trace), trace_instruction_count, trace_refs, comments, comments_rep


def fingerprint_functions(segments):
    """
    Create fingerprints for functions
    """

    log2 = math.log(2)
    progress = ProgressBar('  functions\t\t\t')
    instruction = ida.insn_t()
    functions = []
    count = ida.get_func_qty()
    for n in range(count):
        progress.update(n / count)

        # gather info
        function = ida.getn_func(n)
        fn_start = function.start_ea
        fn_end = function.end_ea
        fn_flags = ida.get_flags(fn_start)
        fn_name = ida.get_name(fn_start)
        fn_type = idc.get_tinfo(fn_start)
        fn_flags = function.flags

        if is_address_fingerprintable(fn_start, segments):
            # signature
            size = min(fn_end - fn_start, signature_size)
            signature = signature_size * [None]
            signature_bytes = ida.get_bytes(fn_start, size)
            n = 0
            maxn = 0
            while n < size:
                # first instruction byte
                signature[n] = ord(signature_bytes[n])
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
                        signature[o] = ord(signature_bytes[o])

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
            'tinfo': fn_type,
            'signature': tuple(signature),
            'fingerprint': tuple(trace),
            'refs': refs,
            'cmt': ida.get_func_cmt(function, False),
            'cmt_rep': ida.get_func_cmt(function, True),
            'code_cmt': comments,
            'code_cmt_rep': comments_rep,
            'user': ida.has_user_name(fn_flags),
            'flags':  fn_flags,
            'public': ida.is_public_name(fn_start),
            'weak': ida.is_weak_name(fn_start),
            'strong': instruction_count >= strong_match_fn_size})

    progress.finish()
    return functions


def enumerate_refs(ea, block_start, block_end):
    """
    Enumerate forward references
    """

    max_addr = 0xff00000000000000 if idc.__EA64__ else 0xff000000
    external_refs = []
    xb = ida.xrefblk_t()
    ref = xb.first_from(ea, ida.XREF_ALL)
    while ref:
        to = xb.to
        if not xb.user and to < max_addr:
            if not (block_start <= to < block_end):
                external_refs.append(to)
        ref = xb.next_from()

    return external_refs


def fingerprint_data_places(segments):
    """
    Create fingerprints for data
    """

    progress = ProgressBar('  data\t\t\t')
    data = []
    count = ida.get_nlist_size()
    for n in range(count):
        progress.update(n / count)

        # collect information
        data_start = ida.get_nlist_ea(n)
        flags = ida.get_flags(data_start)
        if not ida.is_data(flags):
            continue
        name = ida.get_nlist_name(n)

        if ida.is_struct(flags):
            tinfo = idc.get_tinfo(data_start)
            opinfo = ida.opinfo_t()
            opinfo = ida.get_opinfo(opinfo, data_start, 0, flags)
            size = ida.get_data_elsize(data_start, flags, opinfo)
        else:
            size = ida.get_item_size(data_start)
            tinfo = None
        data_bytes = ida.get_bytes(data_start, size)

        # ignore paddings
        if all([byte == '\xcc' for byte in data_bytes]):
            continue

        # collect external references
        data_refs = {}
        for ea in range(data_start, data_start + size):
            refs = enumerate_refs(ea, data_start, data_start + size)
            if refs:
                data_refs[ea - data_start] = refs

        # fingerprint
        if (is_address_fingerprintable(data_start, segments) and
            not data_refs and
            sum(1 for byte in data_bytes if byte not in useless_bytes) >= useful_bytes_count):
            signature = tuple(map(ord, data_bytes[:signature_size]))
            fingerprint = fnv_start
            for byte in data_bytes:
                fingerprint = fnv_hash(fingerprint, ord(byte))
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
            'tinfo': tinfo,
            'size': size,
            'signature': signature,
            'fingerprint': fingerprint,
            'cmt': comments,
            'cmt_rep': comments_rep,
            'refs': {},
            'user': ida.has_user_name(flags),
            'public': ida.is_public_name(data_start),
            'weak': ida.is_weak_name(data_start),
            'strong': size >= strong_match_data_size})

    progress.finish()
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

    resolved_refs = {}
    for pos, refs in refs.items():
        resolved = []
        for ref in refs:
            node = node_intervals.find(ref)
            name, offset = ref_to_symbol(ref, node)
            if name is None:
                name = unknowns.setdefault(ref, (len(unknowns),))

            resolved.append((name, offset))
        resolved_refs[pos] = tuple(resolved)

    return resolved_refs


def save_fdb(filename, db):
    """
    Save fingerprints into a filename
    """

    with io.BufferedWriter(gzip.open(filename, 'wb')) as fd:
        pickle.dump(db, fd, pickle.HIGHEST_PROTOCOL)


def load_fdb(filename):
    """
    Loads fingermatch database
    """

    with io.BufferedReader(gzip.open(filename, 'rb')) as fd:
        return pickle.load(fd)


def build_signature_matcher(nodes):
    """
    Builds datastructure for matching signatures
    """

    progress = ProgressBar('building matching structures\t')
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
    Verifies if strong nodes are unambiguous, possibly removing strong attribute
    """

    progress = ProgressBar('  checking uniqueness\t\t')
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

    print('  fingerprint count\t\t{}'.format(node_count))
    print('postprocessing')

    node_intervals = IntervalTree([(node['ea'], node['ea'] + node['size'], node) for node in nodes])

    # resolve references
    progress = ProgressBar('  resolving references\t\t')
    unknowns = {}
    reference_count = 0
    for n, node in enumerate(nodes):
        progress.update(n / node_count)
        node['refs'] = resolve_refs(node['refs'], node_intervals, unknowns)
        for pos, refs in node['refs'].items():
            reference_count += len(refs)
    progress.finish()
    print('  reference count\t\t{}'.format(reference_count))
    print('  reference unknowns\t\t{}'.format(len(unknowns)))

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
    print('saving fingerprints to\t\t{}'.format(filename))
    save_fdb(filename, {
        'nodes': nodes,
        'patterns': patterns,
        'patterns_unknown': patterns,
        'names': names,
        'types': types,
    })

    print('done\n')


def match_refs(match_ea, match_refs, candidates, names, check=True):
    """
    Match forward refrences to set of candidates
    """

    mpositions = match_refs.keys()
    mpositions.sort()
    mcount = len(mpositions)
    mnames = set(mcandidate['name'] for mcandidate in candidates)

    # inspect all candidates
    survived = []
    guesses = {}
    for candidate in candidates:
        # check if all references are mached
        if check:
            if mcount != len(candidate['refs']):
                continue

            cpositions = candidate['refs'].keys()
            cpositions.sort()
            if mpositions != cpositions:
                continue

        survived.append(candidate)

        # enumerate positions
        for pos in mpositions:
            mrefs = match_refs[pos]
            crefs = candidate['refs'][pos]

            # match references
            ceas = []
            for mdst, (cdst, cdst_offset) in zip(mrefs, crefs):
                cnode = names.get(cdst)
                if cnode is None:
                    cea = mdst
                elif cnode['type'] == 'data':
                    cea = mdst - cdst_offset
                elif cnode['type'] == 'function':
                    mfunction = ida.get_func(mdst)
                    if mfunction is None:
                        cea = mdst
                    else:
                        cea = mfunction.start_ea
                else:
                    assert False, 'unknown node type {}'.cnode['type']
                ceas.append(cea)

            # apply names for all candidates
            for cea in ceas:
                evidence = guesses.setdefault(match_ea, {})
                evidence[cea] = evidence.get(cea, set()) | mnames

    return survived, guesses


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
        group_refs = tuple((pos, len(refs)) for pos, refs in candidate['refs'].items())
        group_key = (candidate['fingerprint'], group_refs)
        group = candidate_groups.setdefault(group_key, [])
        group.append(candidate)

    # filter candidates by function trace
    survivals = []
    for (ctrace, crefs), candidate_members in candidate_groups.items():
        crefs = dict(crefs)
        ctrace_blocks = len(ctrace)
        cposition_to_ea = {}

        # function trace compilation and matching
        survived = True
        trace_block_index = 0
        trace_refs = {}
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
            ccount, chash, cdref_count, ccref_types, cnext, cpops = ctrace[trace_block_index]

            # fingerprint trace block
            block_cref_counts = {}
            block_dref_counts = {}
            block_crefs = 0
            block_drefs = 0
            block_hash = 0
            ccref_count = len(ccref_types)
            ccref_type_index = 0
            mismatch_reason = None
            for n in range(ccount):
                # decode instruction
                size = ida.decode_insn(instruction, ea)
                if size == 0:
                    mismatch_reason = 'invalid instruction inside trace block {}'.format(trace_block_index)
                    survived = False
                    break

                # fingerprint instruction
                instruction_hash, mcrefs, mdrefs = fingerprint_instruction(instruction)
                block_hash = (block_hash + instruction_hash) & 0xffffffffffffffff
                cposition_to_ea[(trace_block_index, instruction_hash)] = ea

                # add drefs to trace
                for n, ref in mdrefs:
                    pos = (trace_block_index, instruction_hash, 'd', n)
                    if pos not in crefs:
                        mismatch_reason = 'dref {} not found among candidate refs'.format((trace_block_index, pos))
                        survived = False
                        break
                    refs = trace_refs.setdefault(pos, [])
                    refs.append(ref)
                    block_dref_counts[pos] = block_dref_counts.setdefault(pos, 0) + 1
                    block_drefs += 1
                if not survived:
                    break

                # add crefs to trace
                for n, ref in mcrefs:
                    if ccref_type_index >= ccref_count:
                        mismatch_reason = 'block {} has more crefs than expected'.format(trace_block_index)
                        survived = False
                        break

                    pos = (trace_block_index, instruction_hash, 'c', n)
                    ccref_type = ccref_types[ccref_type_index]

                    if ccref_type == 'i':
                        stack.append(ref)
                    elif ccref_type == 'e':
                        if pos not in crefs:
                            mismatch_reason = 'cref {} not found among candidate refs'.format((trace_block_index, pos))
                            survived = False
                            break
                        refs = trace_refs.setdefault(pos, [])
                        refs.append(ref)
                        block_cref_counts[pos] = block_cref_counts.setdefault(pos, 0) + 1
                    else:
                        assert False, 'unknown cref type {}'.format(ccref_type)

                    block_crefs += 1
                    ccref_type_index += 1
                if not survived:
                    break

                ea += size
            if not survived:
                break

            # check block hash
            if block_hash != chash:
                mismatch_reason = 'block {} has mismatched hash'.format(trace_block_index)
                survived = False
                break

            # check dref counts
            if block_drefs != cdref_count or any(crefs[pos] != count for pos, count in block_dref_counts.items()):
                mismatch_reason = 'dref counts does not match in block {}'.format(trace_block_index)
                survived = False
                break

            # check cref counts
            if block_crefs != len(ccref_types) or any(crefs[pos] != count for pos, count in block_cref_counts.items()):
                mismatch_reason = 'cref counts does not match in block {}'.format(trace_block_index)
                survived = False
                break

            # advance to next block
            if cnext:
                stack.append(ea)

            # clear stack
            if len(stack) < cpops:
                mismatch_reason = 'block {} does not have enough working stack space to advance'.format(trace_block_index)
                survived = False
                break
            if cpops:
                stack = stack[:-cpops]

            trace_block_index += 1

        # was candidate succesful match?
        if survived:
            survivals = candidate_members
            refs = trace_refs
            break

    if not survived:
        return
    candidates = survivals

    # check references
    candidates, guesses_from_refs = match_refs(start, trace_refs, candidates, names, check=False)
    if not candidates:
        return

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
    explored_ranges = []
    count = ida.get_func_qty()
    progress = ProgressBar('  functions\t\t\t')
    for n in range(count):
        progress.update(n / count)

        function = ida.getn_func(n)
        fn_start = function.start_ea
        fn_end = function.end_ea
        explored_ranges.append((fn_start, fn_end))
        if not is_address_fingerprintable(fn_start, segments):
            continue

        # signature match
        size = min(fn_end - fn_start, signature_size)
        signature_bytes = ida.get_bytes(fn_start, size)
        snodes = None
        candidates = []
        for n in range(size):
            candidates, snodes = patterns.match(ord(signature_bytes[n]), snodes)
            if not snodes:
                candidates = []
                break
        candidates = [c for c in candidates if c['type'] == 'function']
        if not candidates:
            continue

        # match candidates function trace
        match_function_candidates(fn_start, fn_end, candidates, names, guesses, position_to_ea)

    progress.finish()

    return explored_ranges


def match_data_candidates(start, data_bytes, candidates, guesses):
    """
    Match data candidates on given binary location
    """

    if all(byte == '\xff' for byte in data_bytes):
        return

    fingerprint = fnv_start
    for n, byte in enumerate(data_bytes):
        fingerprint = fnv_hash(fingerprint, ord(byte))
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
    explored_ranges = []
    progress = ProgressBar('  data\t\t\t')
    for n in range(count):
        progress.update(n / count)

        # collect information
        data_start = ida.get_nlist_ea(n)
        flags = ida.get_flags(data_start)

        if ida.is_struct(flags):
            opinfo = ida.opinfo_t()
            opinfo = ida.get_opinfo(opinfo, data_start, 0, flags)
            size = ida.get_data_elsize(data_start, flags, opinfo)
        else:
            size = ida.get_item_size(data_start)
        explored_ranges.append((data_start, data_start + size))

        if not ida.is_data(flags):
            continue
        if not is_address_fingerprintable(data_start, segments):
            continue

        data_bytes = ida.get_bytes(data_start, size)

        # signature match
        snodes = None
        candidates = []
        for n in range(min(size, signature_size)):
            candidates, snodes = patterns.match(ord(data_bytes[n]), snodes)
            if not snodes:
                candidates = []
                break
        candidates = [c for c in candidates if c['type'] == 'data']
        if not candidates:
            continue

        # fingerprint match
        match_data_candidates(data_start, data_bytes, candidates, guesses)
    progress.finish()

    return explored_ranges


def prune_guesses(guesses, strong_guesses, match_eas, match_names):
    """
    Prune guesses based on matched evidence
    """

    # prune guesses
    for ea in match_eas:
        del guesses[ea]

    # prune evidence drafts by strong matches
    match_names_set = set(match_names.keys())
    for ea, evidence in guesses.items():
        for source in evidence.keys():
            evidence[source] -= match_names_set
            if not evidence[source]:
                del evidence[source]

    # prune evidence drafts by strong source drafts domination
    for ea, evidence in guesses.items():
        strong_drafts = set()
        for source, drafts in evidence.items():
            if source in match_eas:
                strong_drafts |= drafts
        if strong_drafts:
            strong_guesses.add(ea)
            for source in evidence.keys():
                evidence[source] &= strong_drafts
                if not evidence[source]:
                    del evidence[source]

    # prune empty guesses
    for ea in guesses.keys():
        if not guesses[ea]:
            del guesses[ea]


def match_evidence_level(level, matches, matched_names, guesses, strong_guesses):
    """
    Match items from evidence fingerprints at given evel
    """

    print('  {} evidence'.format(level))
    while True:
        # collect matches
        new_match_names = {}
        new_match_eas = set()
        ambiguous_names = set()
        for ea, evidence in guesses.items():
            if level == 'undeniable':
                level_condition = 'strong' in evidence and len(evidence) >= 2
            elif level == 'strong':
                level_condition = 'strong' in evidence
            elif level == 'good':
                level_condition = len(evidence) >= 3
            elif level == 'weak':
                level_condition = len(evidence) >= 2 and matches
            elif level == 'doubtful':
                level_condition = len(evidence) >= 1 and matches
            else:
                assert False, 'unknown evidence level {}'.format(level)

            if level_condition or ea in strong_guesses:
                drafts = evidence.values()
                if not drafts:
                    continue
                draft_intersection = set.intersection(*drafts)
                if len(draft_intersection) == 1:
                    match = draft_intersection.pop()
                    # test for ambiguity
                    if match in new_match_names:
                        ambiguous_names.add(match)
                    elif match in matched_names:
                        pass
                    else:
                        new_match_names[match] = ea
                        new_match_eas.add(ea)

            if ida.user_cancelled():
                raise UserInterrupt()

        # remove ambiguous matches
        for match in ambiguous_names:
            ea = new_match_names[match]
            new_match_eas.remove(ea)
            del new_match_names[match]

        if not new_match_names:
            break

        # add new matches to all matches
        for match, ea in new_match_names.items():
            matches[ea] = match
            matched_names[match] = ea

        # prune guesses
        prune_guesses(guesses, strong_guesses, new_match_eas, new_match_names)

        print('    matches | guesses\t\t{} | {}'.format(len(matches), len(guesses)))


def match_evidence(matches, matched_names, guesses, strong_guesses):
    """
    Match items from evidence fingerprints
    """

    match_evidence_level('undeniable', matches, matched_names, guesses, strong_guesses)
    match_evidence_level('strong', matches, matched_names, guesses, strong_guesses)
    match_evidence_level('good', matches, matched_names, guesses, strong_guesses)
    #match_evidence_level('weak', matches, matched_names, guesses, strong_guesses)
    #match_evidence_level('doubtful', matches, matched_names, guesses, strong_guesses)


def match_unknown(segments, explored, patterns, names, guesses, position_to_ea):
    """
    Match unknown areas
    """

    # build interval tree for explored areas
    explored_intervals = IntervalTree([(start, end, end) for start, end in explored])

    # enumerate segments
    for name, segment_start, segment_end, segment_type in list_segments():
        progress = ProgressBar('  unknown in {}\t\t'.format(name))
        segment_size = segment_end - segment_start
        segment_bytes = ida.get_bytes(segment_start, segment_size)
        segment_snodes = [None] * segment_size

        # collect candidates for each byte
        n = 0
        while n < segment_size:
            # skip already explored areas
            progress.update(n / segment_size)
            interval_end = explored_intervals.find(segment_start + n)
            if interval_end is not None:
                n = interval_end - segment_start
                continue

            # find candidates inside moving window
            byte = ord(segment_bytes[n])
            for s in range(max(0, n - 32), n):
                if segment_snodes[s] is None:
                    segment_snodes[s] = []
                prev_snodes = segment_snodes[s]
                candidates, snodes = patterns.match(byte, prev_snodes)
                segment_snodes[s] = snodes

                fn_candidates = [c for c in candidates if c['type'] == 'function']
                data_candidates = [c for c in candidates if c['type'] == 'data']
                start = segment_start + s
                end = segment_end + s

                # match functions
                if fn_candidates:
                    match_function_candidates(start, end, fn_candidates, names, guesses, position_to_ea)

                # match data
                if data_candidates:
                    sizes = {}
                    for candidate in candidates:
                        group = sizes.setdefault(candidate['size'], [])
                        group.append(candidate)

                    for size, candidates in sizes.items():
                        match_data_candidates(start, segment_bytes[start:start + size], candidates, guesses)

            # no need to check candidates here, length 1 candidates does not exist
            segment_snodes[n] = patterns.match(byte)[1]

            n += 1
        progress.finish()


def match(filename):
    """
    Matches db against fingerprints
    """

    # unpickle fingerprints
    print('loading fingerprints from\t{}'.format(filename))
    db = load_fdb(filename)
    nodes = db['nodes']
    patterns = db['patterns']
    names = db['names']
    types = db['types']

    # print info
    print('  fingerprints\t\t{}'.format(len(nodes)))

    # match fingerprints
    print('matching')
    segments = list_segments()

    guesses = {}
    position_to_ea = {}
    explored = []
    explored.extend(match_functions(segments, patterns, names, guesses, position_to_ea))
    explored.extend(match_data(segments, patterns, names, guesses))
    match_unknown(segments, explored, patterns, names, guesses, position_to_ea)

    # match items based on fingerprint evidence
    matches = {}
    matched_names = {}
    strong_guesses = set()
    match_evidence(matches, matched_names, guesses, strong_guesses)

    # print results
    data_count = 0
    function_count = 0
    for ea, name in matches.items():
        node = names.get(name)
        if node is not None and node['type'] == 'function':
            function_count +=  1
        elif node is not None and node['type'] == 'data':
            data_count +=  1

    print('  function matches\t\t{}'.format(function_count))
    print('  data matches\t\t{}'.format(data_count))
    print('  leftover guesses\t\t{}'.format(len(guesses)))

    # save matches
    idb = ida.get_path(ida.PATH_TYPE_IDB)
    idb_matches = '{}.fingermatch_matches.csv'.format(idb)
    print('writing matches into \t\t{}'.format(idb_matches))

    with open(idb_matches, 'wt') as fd:
        writer = csv.writer(fd)
        for ea, name in matches.items():
            node = names.get(name)
            if node is not None:
                writer.writerow([hex(int(ea)), node['type'], name])

    # save guesses
    idb_guesses = '{}.fingermatch_guesses.json'.format(idb)
    print('writing leftover guesses into \t{}'.format(idb_guesses))

    json_guesses = {}
    for ea, evidence in guesses.items():
        json_evidence = {}
        for source, drafts in evidence.items():
            if not isinstance(source, str):
                json_drafts = [draft if isinstance(draft, str) else 'unknown_{}'.format(draft[0]) for draft in drafts]
                json_evidence[hex(int(source))] = sorted(json_drafts)

        if not json_evidence:
            continue
        json_guesses[hex(int(ea))] = json_evidence

    with open(idb_guesses, 'wt') as fd:
        json.dump(json_guesses, fd, indent=2, sort_keys=True)

    # import types
    matched_functions = 0
    for ea, name in matches.items():
        if names[name]['type'] == 'function':
            matched_functions += 1
    if matched_functions:
        imported_types = import_types(types)
    else:
        print('did not match any functions, skipping other matches')
        return

    # apply names, types and comments to matches
    progress = ProgressBar('applying meta to matches\t')
    match_count = len(matches)
    tinfo = ida.tinfo_t()
    matched_functions = 0
    matched_data = 0
    imported_comments = 0
    for n, (ea, name) in enumerate(matches.items()):
        progress.update(n / match_count)
        if not isinstance(name, str):
            continue

        # name
        node = names[name]
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

        # type
        if node['tinfo'] is not None:
            tinfo.deserialize(None, *node['tinfo'])
            ida.apply_tinfo(ea, tinfo, ida.TINFO_GUESSED)

        # comments, flags
        if node['type'] == 'data':
            for pos, comment in node['cmt'].items():
                ida.set_cmt(ea + pos, comment, False)
                imported_comments += 1
            for pos, comment in node['cmt_rep'].items():
                ida.set_cmt(ea + pos, comment, True)
                imported_comments += 1

            matched_data += 1
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
                imported_comments += 1
            if node['cmt_rep'] is not None:
                ida.set_func_cmt(function, node['cmt_rep'], True)
                imported_comments += 1

            for pos, comments in node['code_cmt'].items():
                if (name, ea) in position_to_ea:
                    ida.set_cmt(position_to_ea[(name, ea)][pos], '\n'.join(comments), False)
                    imported_comments += 1
            for pos, comments in node['code_cmt_rep'].items():
                if (name, ea) in position_to_ea:
                    ida.set_cmt(position_to_ea[(name, ea)][pos], '\n'.join(comments), True)
                    imported_comments += 1

            matched_functions += 1
    progress.finish()

    print('statistics')
    print('  matched functions\t\t{}'.format(matched_functions))
    print('  matched data \t\t{}'.format(matched_data))
    print('  imported types \t\t{}'.format(imported_types))
    print('  imported comments \t\t{}'.format(imported_comments))


def fingermatch_merge(filenames, output_name, exclusions=None):
    """
    Merge several fingematch databases into one
    filenames: list of fingerprint databases to merge
    output_name: name of output dadtabase
    exclusions: list of regexps, names matching any of these will be excluded
    """

    if exclusions is None:
        exclusions = []

    # compile exclusions
    re_exclusions = [re.compile(exclusion, re.I) for exclusion in exclusions]

    # load databases
    fdbs = {}
    for filename in filenames:
        print('loading fingerprints from\t{}'.format(filename))
        fdbs[filename] = load_fdb(filename)

    names = {}
    nodes = []

    print('merging')

    # find functions conflicts
    name_to_function = {}
    all_functions = 0
    progress = ProgressBar('  functions\t\t\t')
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
    progress = ProgressBar('  data\t\t\t')
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
    progress = ProgressBar('  types\t\t\t')
    for n, (name, types) in enumerate(name_to_type.items()):
        progress.update(n / count)
        tinfos = [type['tinfo'] for type in types]
        if len(set(tinfos)) == 1:
            unambiguous_types.append(types[0])
    progress.finish()

    print('  used functions\t\t{} / {}'.format(len(unambiguous_functions), all_functions))
    print('  used data\t\t\t{} / {}'.format(len(unambiguous_data), all_data))
    print('  used types\t\t\t{} / {}'.format(len(unambiguous_types), all_types))

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
    progress = ProgressBar('  cleaning references\t\t')
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
    print('  cleaned references\t\t{} / {}'.format(unknown_count, all_ref_count))

    # verify node strongness (must have unique fingerprint)
    verify_strongness(nodes)

    # signature matching
    patterns, patterns_unknown = build_signature_matcher(nodes)

    # pickle fingerprints
    print('saving fingerprints to\t\t{}'.format(output_name))
    save_fdb(output_name, {
        'nodes': nodes,
        'patterns': patterns,
        'patterns_unknown': patterns_unknown,
        'names': names,
        'types': unambiguous_types,
    })


def fingermatch_collect(filename):
    """
    Collect functions, data, types and comments and save them into database
    filename: path to fingerprint database to save collected items to
    """

    ida.show_wait_box('collecting fingerprints')
    try:
        collect(filename)
    except UserInterrupt:
        print('user interrupted')
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
        print('user interrupted')
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
        delattr(module, name)
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

        ida.info('FingerMatch plugin\n\nTo collect fingerprints go to View -> collect fingerprints.\nTo match stored fingerprints go to View -> match fingerprints.')


def PLUGIN_ENTRY():
    """
    FingerMatch IDA plugin entrypoint
    """

    if ida.IDA_SDK_VERSION < 700:
        print('FingerMatch is requires IDA 7.0 and newer versions.')
        return

    return FingerMatch()
