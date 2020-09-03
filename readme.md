# FingerMatch

IDA plugin for collecting functions, data, types and comments from analysed binaries
and fuzzy matching them in another binaries.

autor: Jan Prochazka
licence: none, public domain
home: https://github.com/jendabenda/fingermatch


## Usage
 * fingerprint libraries and then match them in binaries you want to anlayze to save work,
   you can focus only on unseen and interesting parts
 * resume analysis when new version of previously analyzed binary is out, so you don't need to
   reverse engineer everything from scratch
 * anything what fits


## Features
 * fuzzy function matching
 * data, types, comments matching
 * easy to use


## Installation
 * works with IDA 7.4+, python 3
 * copy `fingermatch.py` into `IDA-path/plugins`


## UI
 * menu View -> Collect fingerprints - collects fingerprints and save them into filename
 * menu View -> Match fingerprints - loads fingerprints from filename and match them against
   current binary


## Public Python API
 * available to IDA public namespace
 * `fingermatch_collect(filename)` - collects fingerprints and save them into filename
 * `fingermatch_match(filename)` - loads fingerprints from filename and match them against current binary
 * using Python API is slow, despite running the same code, IDA developers know the answer


## Libraries workflow
 * compile library with debugging symbols (\Z7 or \Zi switch with msvc)
 * autoanalyze binary with IDA
 * collect fingerprints with FingerMatch
 * match fingerprints wherever you want

## Resumption workflow
 * open binary, analyze it
 * collect fingerprints with FingerMatch
 * when new binary version is out, open new version
 * match saved fingerprints


## Fingerprints
Function fingerprints are bases on control flow traces allowing to match the same function
with shuffled basic block, different register allocation or instruction scheduling.
Fingerprints of data, types and comments are also matched.

Detailed documentation is at the begining of the `fingermatch.py` file.
