// SPDX-License-Identifier: AGPL-3.0-or-later
// Minimal typing for the fs-ext native binding: only flockSync is used.

declare module 'fs-ext' {
  export function flockSync(fd: number, flags: 'sh' | 'ex' | 'shnb' | 'exnb' | 'un'): void;
}
