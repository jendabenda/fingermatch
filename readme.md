# FingerMatch

IDA plugin for collecting functions, data, types and comments from analysed binaries
and fuzzy matching them in another binaries.

> autor: Jan Prochazka<br>
> licence: none, public domain<br>
> home: https://github.com/jendabenda/fingermatch<br>


## Usage
 * fingerprint libraries and then match them in binaries you want to anlayze,
   you can focus only on unseen and interesting parts
 * resume analysis when new version of previously analyzed binary is out, no need to
   reverse engineer everything from scratch
 * anything what fits


## Features
 * fuzzy function matching
 * data, types, comments matching
 * can correctly match small functions
 * easy to use


## Installation
 * works with IDA 7.4+, Python 3
 * copy `fingermatch.py` into `/plugins` folder of IDA


## UI
 * menu `View -> Collect fingerprints` - collects fingerprints and save them into filename
 * menu `View -> Match fingerprints` - loads fingerprints from filename and match them against
   current binary


## Python API
 * available from IDA console
 * `fingermatch_collect(filename)` - collects fingerprints and save them into fingerprint database
 * `fingermatch_match(filename)` - loads fingerprints from fingerprint database and match them against analysed binary


## Libraries workflow
 * compile library with debugging symbols (`\Z7` or `\Zi` switch with msvc)
 * autoanalyze binary with IDA and pdb symbols
 * collect fingerprints with FingerMatch
 * match fingerprints wherever you want

## Resumption workflow
 * open binary, analyze it
 * collect fingerprints with FingerMatch
 * when new binary version is out, open new version
 * match saved fingerprints


## Fingerprints
Function fingerprints are based on control flow traces allowing to match the same function
with shuffled basic block, different register allocation or instruction scheduling.
Fingerprints of data, types and comments are also matched. In addition matching considers
whole reference graph, so it has high chance to pinpoint correct names. Matching is tuned
to have low false positive matches.

Detailed documentation is at the begining of the `fingermatch.py` file.
