# MyPyDbg
## Trivial debugger implementation for x64 Microsoft Windows system

The project is inspired from Gray Hat Python (Justin Seitz, 2009). The notable distinctions being:

- [x] Transition from python 2 to python 3. (Tested on python 3.10)
- [x] Support for x86-64 bit executables.
- [x] Mitigation of Access Violations encountered after software-breakpoints.
- [ ] Support for x86 executables through WOW64.
- [ ] Interactive pager-based interface.
