// SPDX-License-Identifier: AGPL-3.0-or-later
// Namespace control file name (Blueprint §5.3), in a module without the native
// lock binding, so the offline verifier never loads fs-ext.

export const WRITER_LOCK_NAME = '.writer.lock';
