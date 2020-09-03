# FingerMatch

IDA plugin for collecting functions, data, types and comments from analysed binaries
and fuzzy matching them in another binaries.

autor: Jan Prochazka
licence: none, public domain
home: https://github.com/jendabenda/fingermatch


## Use
 * fingerprinting libraries and then matching them in binaries you want to anlayze to save work
   focusing only on unseen and interesting parts
 * resuming analysis when new version of previously analyzed binary is out, so you don't need to
   reverse engineer everything from "scratch"
 * anything what fits


## Installation
 * copy `fingermatch.py` into `IDA-path/plugins`
 * works with IDA 7.2 other versions will be tested soon


## UI
 * menu View -> Collect fingerprints - collects fingerprints and save them into filename
 * menu View -> Match fingerprints - loads fingerprints from filename and match them against
   current binary


## Public Python API
 * available to IDA public namespace
 * `fingermatch_collect(filename)` - collects fingerprints and save them into filename
 * `fingermatch_match(filename)` - loads fingerprints from filename and match them against current binary
 * `fingermatch_merge(filenames, output_name, exclusions)` - merges databases in filenames into
 * using Python API is slow, despite running the same code, IDA developers know the answer


## Libraries workflow
 * compile library with debugging symbols (\Z7 or \Zi switch with msvc)
 * autoanalyze binary with IDA
 * collect fingerprints with FingerMatch
 * match fingerprints whenever you want

## Resumption workflow
 * open binary, analyze it
 * collect fingerprints with FingerMatch
 * when new version is out, open new version
 * match saved fingerprints


## Fingerprints
Function fingerprints are bases on control flow traces allowing to match the same function with shuffled basic block, different register allocation or instruction scheduling. Fingerprints of data are also matched, ingoring pointers to be position independent.

Detailed documentation is at the begining of the `fingermatch.py` file.
