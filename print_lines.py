import sys
path=r'internal\scan\scanner.go'
with open(path,'r',encoding='utf-8') as f:
    for i,l in enumerate(f,1):
        if i<=100:
            sys.stdout.write(f"{i:4d}: {l.replace('\t','[TAB]')}" )
