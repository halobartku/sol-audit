import json,sys
d=json.load(open(sys.argv[1],encoding="utf-8"))
def on(e,v): return (e.get(v) or {}).get("on_target",0)
nom=real=0; bad=[]
for e in sorted(d,key=lambda x:x["class"]):
    i,s_,r=on(e,"insecure"),on(e,"secure"),on(e,"recommended")
    det=i>0; fired=s_>0 or r>0; rl=det and not fired
    nom+=det; real+=rl
    if det and fired: bad.append(e["class"])
print(f"NOMINAL {nom}/{len(d)}   REAL {real}/{len(d)}")
if bad: print("nominal-only (odpala tez na naprawionym):", ", ".join(bad))
