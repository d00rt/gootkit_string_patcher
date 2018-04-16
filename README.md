# gootkit_string_patcher

## ANALYSIS
    http://reversingminds-blog.logdown.com/posts/7369479

## DESCRIPTION
    A python script using radare2 for decrypt and patch the strings of GootKit malware


## OPTIONS
    -o [JSON|PLAINTEXT]        print decrypted strings in the given format


## EXAMPLES
    patch_gootkit.py unpacked_gootkit.exe

    patch_gootkit.py unpacked_gootkit.exe -o

    patch_gootkit.py unpacked_gootkit.exe -o json

## OUTPUT FILE
    unpacked_gootkit.exe__patched

