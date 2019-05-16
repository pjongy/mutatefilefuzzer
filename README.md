# MutateFuzzer

Windows mutate binary fuzzer for python 2.7.x and python 3.x<br/>
debugger and defines are readjusted from pydbg<br/>

You can use fuzzer just modify MutateFuzzer class<br/>
If you want more action in mutate, then just add in self.mutate_functions!

```
-MutateFuzzer
    |_ samplefiles      => Mutate sample file
    |_ debugger.py      => x86 debugger readjust pydbg
    |_ defines.py       => x86 structures readjust pydbg
    |_ framework.py        => Abstract implement for fuzzer
    |_ logo.py          => Fuzzing logo
    |_ fuzzer.py        => Real implement fuzzer
    |_ crashBinary.xml  => XML file that includes fuzzing target
```

USAGE

```
> python fuzzer.py crashBinary.xml
> python fuzzer.py [XMLFILENAME]
```


XMLFILE FORMAT
```xml
<root>
  <target>C:\crashBinary.exe</target>
  <gflag>0</gflag>
  <offset>0</offset>
  <filetype>txt</filetype>
  <interval>3</interval>
</root>
```

USAGE FUZZER

```python
import framework
class MutateFuzzer(framework.FileFuzzer):
    def __init__(self, target, file_type, interval):
        framework.FileFuzzer.__init__(self, target, file_type, interval)
        self.mutate_functions = {
            FUNCTION: [MUTATE_BYTES],
            FUNCTION: [MUTATE_BYTES]
        }
        
    def after_run_process(self):
        WHEN DEBUG ENDS FUZZER AUTOMATICALLY RUN THIS FUNCTION
        
    def set_file_size(self):
        INFORM RUN LOOP COUNT TO FUZZER
        (IF DECOMPRESS zip AND REZIP -> CALC UNZIP SIZE)
        self.set_fuzz_iter(file_size) #FUZZER's FUNCTION
        
    def FUNCTION(self, file_name, file_offset, mutate_bytes):
        SHOULD MAINTAIN ARGS AND RETURNS MODE STRING
        return MODE
        
    def log_crash(self, dump_file, dbg, mutate_info):
        SHOULD MAINTAIN ARGS FOR LOGGING IF CRASH OCCUR
        
    def every_iterate(self, iterate):
        EVERY ITERATE RUN FUNCTION

if __name__ == '__main__':
        target_full_path = ["Target program full path for fuzzing"]
        file_type = ["Mutate file_type that is in ./samplefiles/"]
        interval = ["Interval how long wait for"]
        
        fuzzer = MutateFuzzer(target_full_path, file_type, interval)
        fuzzer.set_file_size()
        fuzzer.set_arbitrary_offset(0)
        fuzzer.init_set() #setting mutater environ
        fuzzer.start()
```

crashBinary is sourcecode that include vulnerability for testing fuzzer can catch exceptions
