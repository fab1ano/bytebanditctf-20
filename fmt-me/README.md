fmt-me
======

In this challenge the binary `fmt` was given.
The binary (arch: `amd64`) is `Partial RELRO` and uses stack canaries and the NX bit. The binary is position dependent.

The decompilation of the main function looks like this:

```C
char other_buf[0x100];

int main(int argc, const char **argv, const char **envp) {
  char buf[0x100];

  setvbuf(stdout, 0, 2, 0);
  setvbuf(stdin, 0, 2, 0);

  puts("Choose your name");
  puts("1. Lelouch 2. Saitama 3. Eren");
  printf("Choice: ");

  if (get_int() == 2) {
    puts("Good job. I'll give you a gift.");
    read(0, buf, 0x100);
    snprintf(other_buf, 0x100, buf);
    system("echo 'saitama, the real hero'");
  }

  return 0;
}
```

To take over the control flow we use a blind format string attack in `snprintf`.
The first step is to set the `.got` entry of `system` to the beginning of `_start` so that we can execute the whole `main` function again.
Since `system` is not resolved yet when control flow reaches `snprintf`, it is sufficient to change the least significant byte.
For this we use the following format string: `"A"*0xC0 + "%31$hhnA" + got["system"]`.
So, `0xC0` is the new value of the `.got` entry of `system`, which now points to `_start`.
In the format string `31` is the number of the argument, which refers to `got["system"]` (the address of `system` in `.got`).

After that we are able to execute another format string.
With this format string we set the `snprintf` entry in `.got` to `0x401056` which is the address of the `system` resolve stub in `.plt`.
This format string must include `/bin/sh;` in the beginning since it will be passed to the call to `system` at the next execution of `snprintf`.
One may use `"/bin/sh;" + f"%4$0{value-8}d" + "%10$ln" + padding + got["snprintf"]` to "output" `value` many bytes (the string `/bin/sh;` plus a number padded to `value-8`-many bytes) before writing that number to the `.got` entry of `snprintf`.

Thus, since the `main` function is executed again when calling `system`, we can issue a call to `system("/bin/sh;")` by choosing "2" a third time and providing an arbitrary string to `read` before `snprintf` gets called and starts a shell.
