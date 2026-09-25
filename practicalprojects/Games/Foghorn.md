# Foghorn

I built a small two-player game called Foghorn and wanted to share it [here](https://lattice-walker.github.io/Foghorn/). I made this mostly for my own amusement and figured others might enjoy trying it too. 

## 1. The sudoku generator

The generator doesn't handcraft a puzzle. It builds a complete valid solution first, then removes clues while keeping the puzzle uniquely solvable.

It starts from an empty 9×9 grid and solves it with a randomized branch order, so the final solution is random but still legal. Clues then get carved away in random order, optionally removing symmetric pairs, and each removal only sticks if the remaining grid still has exactly one solution.

This is the right place for brute force, since uniqueness is a property of the clue set itself, not of how a human plays. The engine keeps that boundary strict: the exact-cover solver only runs during generation and uniqueness checks. The live gameplay solver never sees the answer key and has to reason from the puzzle state alone.

## 2. Static website bi-player technique

This is a static site, so there's no backend and no signalling server to introduce the two browsers.

The host browser creates a WebRTC offer and gathers ICE candidates, then encodes that offer into a text string and sends it to the other player through whatever out-of-band channel they already use. The joining browser pastes the offer, creates an answer, and sends it back. Once both SDPs are exchanged, the browsers open a direct data channel and the game traffic runs over it.

GitHub Pages doesn't host the session, only the files. STUN servers handle NAT traversal, so they learn that some client is looking for a peer, not what the game is or what the players are saying — the game data itself stays in the peer-to-peer connection.

## 3. The variants and their metas

The supported variants are deliberately small and local. Foghorn isn't a full CTC-style variants catalogue; it supports marker families that can be expressed as short, provable relations between cells and sent without revealing a digit:

- Classic Sudoku as the base rule
- Kropki (white dot = consecutive, black dot = double)
- XV (sum 5 or sum 10)
- Greater-than inequalities
- Whisper lines
- Same and opposite parity
- Anti-knight, anti-king, and no-neighbours badges

The palette stays intentionally limited to these relations. The associated metas are the standard Sudoku deductions plus whatever variant-specific propagation those relations create: naked singles, hidden singles, full houses, locked candidates (pointing and claiming), naked/hidden subsets, basic fish (X-wing, swordfish, jellyfish), and short chains or local reasoning that fires when a marker constrains a small set of cells. Variant logic isn't a separate engine — it's the same constraint propagation applied to those local relationships.

So Foghorn supports the local-relation family of Sudoku variants, with metas that are just the normal classical solving techniques plus the deductions those local rules enable. Whole-grid variants and exotic cages or lines aren't in the live palette.
