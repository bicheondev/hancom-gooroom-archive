#!/usr/bin/env python3
"""Fail-closed exact-source/debug recovery for Hancom Gooroom integration-applet."""
from __future__ import annotations

import argparse, hashlib, html.parser, json, re, shutil, subprocess, sys, time
import urllib.error, urllib.parse, urllib.request
from pathlib import Path

PKG = "gooroom-integration-applet"
VER = "0.3.1+grm3u1+han3u3"
POOL = "https://update.hancomgooroom.com/hancom/pool/main/g/gooroom-integration-applet"
TARGET = f"{POOL}/{PKG}_{VER}_amd64.deb"
TARGET_SHA = "1771ded81658d0e4bcce730ab69d162a1e58327cdabf1918c341cfbd02f495a9"
UA = "Hancom-Gooroom-ARM64-Recovery/7"


def cmd(args, cwd=None, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE):
    p = subprocess.run(args, cwd=cwd, text=True, stdout=stdout, stderr=stderr)
    if check and p.returncode:
        raise RuntimeError(f"command failed ({p.returncode}): {' '.join(map(str,args))}\n{p.stdout or ''}\n{p.stderr or ''}")
    return p


def sha(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest()


def dump(path, obj):
    path = Path(path); path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)+"\n", encoding="utf-8")


def fetch(url, dest, required=False, tries=4, timeout=120):
    dest = Path(dest); dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix+".part"); error = None; status = None
    for n in range(1, tries+1):
        try:
            req = urllib.request.Request(url, headers={"User-Agent":UA,"Accept":"*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r, tmp.open("wb") as out:
                status = getattr(r,"status",None); shutil.copyfileobj(r,out,1<<20)
            tmp.replace(dest)
            return {"status":"downloaded","path":dest.as_posix(),"size":dest.stat().st_size,"sha256":sha(dest),"http_status":status}
        except urllib.error.HTTPError as e:
            status=e.code; error=f"HTTP {e.code}: {e.reason}"
            if e.code in {400,401,403,404,410}: break
        except Exception as e:
            error=f"{type(e).__name__}: {e}"
        tmp.unlink(missing_ok=True)
        if n < tries: time.sleep(min(n*2,8))
    tmp.unlink(missing_ok=True)
    if required: raise RuntimeError(f"required download failed: {url}: {error}")
    return {"status":"unavailable","http_status":status,"error":error}


def field(deb, name):
    return cmd(["dpkg-deb","-f",str(deb),name]).stdout.strip()


def build_id(path):
    p=cmd(["readelf","-n",str(path)],check=False)
    m=re.search(r"Build ID:\s*([0-9a-fA-F]+)",p.stdout or "")
    return m.group(1).lower() if m else None


def elf(path):
    try:
        return Path(path).open("rb").read(4)==b"\x7fELF"
    except OSError:
        return False


class Links(html.parser.HTMLParser):
    def __init__(self): super().__init__(); self.items=[]
    def handle_starttag(self,tag,attrs):
        if tag.lower()=="a":
            h=dict(attrs).get("href")
            if h: self.items.append(urllib.parse.unquote(h))


def basename(value):
    p=urllib.parse.urlsplit(value); name=urllib.parse.unquote((p.path if p.scheme else value).rsplit("/",1)[-1]).strip()
    return name if name and name not in {".",".."} and "/" not in name and "\\" not in name and not name.startswith(".") else None


def parse_dsc(path):
    text=Path(path).read_text(encoding="utf-8",errors="replace")
    vm=re.search(r"^Version:\s*(\S+)\s*$",text,re.M)
    sm=re.search(r"^Checksums-Sha256:\s*\n((?:[ \t].*(?:\n|$))+)",text,re.M)
    if not vm or not sm: raise RuntimeError("vendor DSC lacks Version or Checksums-Sha256")
    files={}
    for line in sm.group(1).splitlines():
        p=line.split()
        if len(p)!=3: continue
        digest,size,name=p
        if not re.fullmatch(r"[0-9a-fA-F]{64}",digest) or basename(name)!=name: raise RuntimeError(f"invalid DSC member: {line}")
        files[name]={"sha256":digest.lower(),"size":int(size)}
    if not files: raise RuntimeError("vendor DSC has no SHA-256 members")
    return vm.group(1),files


def inventory(root, out):
    root=Path(root); rows=[]
    for p in sorted(root.rglob("*")):
        if p.is_file() and not p.is_symlink() and p != Path(out): rows.append(f"{p.relative_to(root).as_posix()}\t{p.stat().st_size}")
    Path(out).write_text("\n".join(rows)+( "\n" if rows else ""),encoding="utf-8")


def source_recovery(root, probes):
    src=root/"source"; candidates=[]; errors=[]
    for r in probes:
        if r["status"]=="downloaded" and r["name"].endswith(".dsc"):
            try:
                version,files=parse_dsc(r["path"])
                if version==VER: candidates.append((Path(r["path"]),files))
            except Exception as e: errors.append({"path":r.get("path"),"error":str(e)})
    if len(candidates)!=1:
        dump(src/"dsc-selection.json",{"matching_count":len(candidates),"errors":errors}); return False
    dsc,files=candidates[0]; shutil.copy2(dsc,src/"vendor.dsc")
    lock={"schema":2,"source":PKG,"version":VER,"dsc_sha256":sha(src/"vendor.dsc"),"files":files}; dump(src/"dsc-lock.json",lock)
    available={r["name"]:Path(r["path"]) for r in probes if r["status"]=="downloaded"}
    for name,expected in sorted(files.items()):
        dst=src/name
        if name in available: shutil.copy2(available[name],dst)
        else: fetch(f"{POOL}/{urllib.parse.quote(name)}",dst,required=True,tries=8)
        if dst.stat().st_size!=expected["size"] or sha(dst)!=expected["sha256"]: raise RuntimeError(f"source member mismatch: {name}")
    cmd(["dpkg-source","--no-check","-x","vendor.dsc","extracted"],cwd=src)
    actual=cmd(["dpkg-parsechangelog",f"-l{src/'extracted/debian/changelog'}","-SVersion"]).stdout.strip()
    if actual!=VER: raise RuntimeError(f"extracted source version mismatch: {actual}")
    inventory(src/"extracted",src/"source-tree-inventory.tsv")
    cmd(["tar","-C",str(src/"extracted"),"-cf",str(src/"exact-vendor-source.tar"),"."]); cmd(["xz","-9e","-f",str(src/"exact-vendor-source.tar")])
    return True


def debug_recovery(root, probes):
    targets=[]
    for name in ("libgooroom-integration-applet.so","libnimf-gooroom.so"):
        found=sorted((root/"target").rglob(name))
        if len(found)!=1 or not build_id(found[0]): raise RuntimeError(f"invalid target ELF selection: {name}")
        targets.append({"name":name,"path":found[0].relative_to(root/"target").as_posix(),"build_id":build_id(found[0])})
    target_ids={r["build_id"] for r in targets}; packages=[]; matches=[]
    debs=[Path(r["path"]) for r in probes if r["status"]=="downloaded" and r["name"].endswith((".deb",".ddeb")) and ("dbgsym" in r["name"] or re.search(r"(?:^|[-_])dbg(?:[-_.]|$)",r["name"]))]
    for i,deb in enumerate(sorted(set(debs))):
        extract=root/"debug"/f"package-{i}"; extract.mkdir(parents=True,exist_ok=True)
        try:
            meta={"package":field(deb,"Package"),"version":field(deb,"Version"),"architecture":field(deb,"Architecture")}; cmd(["dpkg-deb","-x",str(deb),str(extract)])
        except Exception as e:
            packages.append({"filename":deb.name,"status":"invalid","error":str(e),"files":[]}); continue
        files=[]
        for p in sorted(extract.rglob("*")):
            if not p.is_file() or p.is_symlink() or not elf(p): continue
            bid=build_id(p); row={"path":p.relative_to(extract).as_posix(),"size":p.stat().st_size,"sha256":sha(p),"build_id":bid,"matches_target_build_id":bid in target_ids}; files.append(row)
            if row["matches_target_build_id"] and meta["version"]==VER and meta["architecture"]=="amd64":
                hit={**row,**meta,"package_filename":deb.name}; matches.append(hit)
                dst=root/"debug/matching"/f"{bid}-{p.name}"; dst.parent.mkdir(parents=True,exist_ok=True); shutil.copy2(p,dst)
                with dst.with_suffix(dst.suffix+".decodedline.txt").open("w") as out: cmd(["readelf","--debug-dump=decodedline",str(p)],check=False,stdout=out,stderr=subprocess.STDOUT)
        packages.append({"filename":deb.name,**meta,"files":files})
    matched={r["build_id"] for r in matches if r.get("build_id")}
    doc={"schema":2,"target_elfs":targets,"target_build_ids":sorted(target_ids),"debug_package_count":len(debs),"debug_packages":packages,"matching_debug_file_count":len(matches),"matching_debug_files":matches,"matching_build_ids":sorted(matched),"exact_matching_debug_payload_recovered":bool(target_ids) and matched==target_ids}
    dump(root/"debug/debug-recovery.json",doc); return doc


def checksums(root):
    root=Path(root); rows=[]
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.name!="LOCKSUMS.sha256": rows.append(f"{sha(p)}  {p.relative_to(root).as_posix()}")
    (root/"LOCKSUMS.sha256").write_text("\n".join(rows)+( "\n" if rows else ""),encoding="utf-8")


def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--workspace",type=Path,default=Path("work/vendor-recovery-v7")); root=ap.parse_args().workspace.resolve()
    if root==Path("/"): raise RuntimeError("refusing / workspace")
    if root.exists(): shutil.rmtree(root)
    for n in ("downloads","target","source","debug","output"): (root/n).mkdir(parents=True,exist_ok=True)
    target=root/"downloads/target.deb"; tr=fetch(TARGET,target,required=True,tries=8)
    if tr["sha256"]!=TARGET_SHA: raise RuntimeError("target SHA-256 mismatch")
    fields={n:field(target,n) for n in ("Package","Version","Architecture")}
    if fields!={"Package":PKG,"Version":VER,"Architecture":"amd64"}: raise RuntimeError(f"unexpected target fields: {fields}")
    (root/"output/target-control-fields.txt").write_text(cmd(["dpkg-deb","-f",str(target)]).stdout,encoding="utf-8"); cmd(["dpkg-deb","-x",str(target),str(root/"target")])
    index=root/"output/pool-index.html"; ir=fetch(f"{POOL}/",index,tries=2,timeout=60); links=[]
    if ir["status"]=="downloaded": parser=Links(); parser.feed(index.read_text(encoding="utf-8",errors="replace")); links=sorted(set(parser.items))
    dump(root/"output/pool-index-links.json",links)
    names={f"{PKG}_{VER}.dsc",f"{PKG}_{VER}.tar.xz",f"{PKG}_{VER}.tar.gz",f"{PKG}_{VER}.tar.bz2",f"{PKG}-dbgsym_{VER}_amd64.deb",f"{PKG}-dbgsym_{VER}_amd64.ddeb",f"{PKG}-dbg_{VER}_amd64.deb"}
    for link in links:
        n=basename(link)
        if n and (VER in n or "dbgsym" in n or re.search(r"(?:^|[-_])dbg(?:[-_.]|$)",n) or n.endswith((".dsc",".tar.xz",".tar.gz",".tar.bz2"))): names.add(n)
    probes=[]
    for n in sorted(names): probes.append({"name":n,"url":f"{POOL}/{urllib.parse.quote(n)}",**fetch(f"{POOL}/{urllib.parse.quote(n)}",root/"downloads"/n,tries=3)})
    dump(root/"output/probe-results.json",probes)
    source=source_recovery(root,probes); debug=debug_recovery(root,probes); debug_ok=debug["exact_matching_debug_payload_recovered"]
    next_action="rebuild exact vendor source for AMD64 and verify against the locked target payload" if source else ("use exact DWARF evidence to complete source reconstruction" if debug_ok else "continue public-history and binary-guided source reconstruction")
    summary={"schema":2,"recovery_generation":"v7","source":PKG,"version":VER,"pool_base":POOL,"target_url":TARGET,"target_deb_sha256":TARGET_SHA,"target_control_fields":fields,"pool_index_status":ir["status"],"pool_index_http_status":ir.get("http_status"),"probe_candidate_count":len(probes),"downloaded_candidate_count":sum(r["status"]=="downloaded" for r in probes),"exact_vendor_source_package_recovered":source,"exact_matching_debug_payload_recovered":debug_ok,"amd64_rebuild_allowed":source,"native_arm64_build_allowed":False,"package_promotion_allowed":False,"iso_assembly_allowed":False,"fail_closed":True,"next_action":next_action}
    dump(root/"output/summary.json",summary); shutil.copy2(root/"debug/debug-recovery.json",root/"output/debug-recovery.json")
    for name in ("dsc-lock.json","source-tree-inventory.tsv"):
        p=root/"source"/name
        if p.exists(): shutil.copy2(p,root/"output"/name)
    inventory(root/"output",root/"output/FILE-INVENTORY.tsv"); checksums(root/"output"); print(json.dumps(summary,indent=2,sort_keys=True)); return 0


if __name__=="__main__":
    try: raise SystemExit(main())
    except Exception as e: print(f"fatal: {type(e).__name__}: {e}",file=sys.stderr); raise
