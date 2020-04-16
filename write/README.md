write
=====

In this challenge the binary `write` and the used `libc-2.27.so` were given.
The binary (arch: `amd64`) is `Full RELRO`, position independent and uses the NX bit. Stack canaries are not used.

## The Vulnerability

The decompilation of the main function looks roughly like this:

```C
int main(void) {
  __int64 *v3;
  __int64 v4;
  char s[2];

  setbuf(stdin, 0LL);
  setbuf(_bss_start, 0LL);

  printf("puts: %p\n", &puts);
  printf("stack: %p\n", &v4);

  while (1) {
    puts("===Menu===");
    puts("(w)rite");
    puts("(q)uit");
    fgets(s, 2, stdin);

    if (s[0] == 'q') {
      break;
    }

    if (s[0] == 'w') {
      printf("ptr: ");
      __isoc99_scanf("%lu", &v3);
      printf("val: ");
      __isoc99_scanf("%lu", &v4);
      *v3 = v4;
    }
  }

  exit(0);
}
```

Thus, we have a stack leak, libc leak, and arbitrary 64-bit write.
But the `main` function never returns since it calls `exit`.

## Exploits

Overall there are at least four different ways to solve this challenge (and probably more).
The approach of each is described here; I implemented the first three approaches.

### _dl_fini
The first way only needs one write: setting the `__rtld_lock_lock_recursive` ptr in the loader to a one_gadget is sufficient, since that function is called by `_dl_fini` in the loader.
Since `_dl_fini` is called by `exit`, we just need to request a `(q)uit`.

But why is `_dl_fini` called by `exit`?
It is passed to the binary from the loader as a callback for program termination.
Thus, it is registered by `atexit` to be called before termination of the program.

It might be necessary to brute force the offset from `libc` to the loader, since that offset depends on different parameters.

### libc .got
A simple way is to overwrite an entry in `.got` with a one_gadget.
One can use `strlen`, which is called by puts.
It might be necessary to set some values on the stack to zero such that the environment and argument pointer are empty.
This approach is doable with two writes.

### atexit
The idea is to overwrite a function which was registered with `atexit`.
These functions are stored in a list, such that we can overwrite one of these function pointers.
Usually, `_dl_fini` is stored in that list, so there is at least one entry.
Nevertheless, these function pointers are mangled (rotated and xor-ed with a static key).

Thus, this attack needs two writes.
With the first write one can set the static mangling key to 0.
Using a second write we replace a function pointer in the `atexit` list with a one_gadget (remember to rotate it back such that it gets rotated to the correct address during demangling).
To call the one_gadget, we only need to `(q)uit` and call `exit`, which triggers the functions registered with `atexit`.

It is necessary to brute force the offset from `libc` to the `ld` data pages, since that offset depends on different parameters such as the set of loaded libraries.

### DT_FINI_ARRAY
Another approach is the `DT_FINI_ARRAY` in `_dl_fini`.
I did not look at this into detail, so I cannot say much about this technique.
The basic idea is that said array also contains function pointers which are called by `_dl_fini`.
Overwriting one of those function pointers with a one_gadget can get you a shell.

