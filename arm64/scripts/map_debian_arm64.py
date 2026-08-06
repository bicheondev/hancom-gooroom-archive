#!/usr/bin/env python3
"""Map the AMD64 binary package lock to exact Debian ARM64 packages."""
import argparse, csv, json, subprocess
from pathlib import Path

REPLACE={
 "binutils-x86-64-linux-gnu":("binutils-aarch64-linux-gnu","same-version","AArch64 binutils replacement"),
 "grub-pc":("grub-efi-arm64","same-version","ARM64 UEFI bootloader replacement"),
 "grub-pc-bin":("grub-efi-arm64-bin","same-version","ARM64 UEFI modules replacement"),
}
OMIT={
 "amd64-microcode":"x86-64 CPU microcode is not applicable to ARM64",
 "intel-microcode":"Intel CPU microcode is not applicable to ARM64",
 "libdrm-intel1":"Intel-only DRM userspace driver is not applicable to ARM64 target",
 "xserver-xorg-video-intel":"Intel-only Xorg driver is not applicable to ARM64 target",
}
CUSTOM_REPLACE={
 "linux-image-5.10.0-23-amd64":("linux-image-5.10.0-23-arm64","rebuild the exact linux 5.10.179-1+grm3u1 source"),
 "linux-image-amd64":("linux-image-arm64","replace the amd64 signed metapackage after kernel rebuild"),
}

def available(conf,name,version):
 p=subprocess.run(["apt-cache","-c",str(conf),"show",f"{name}:arm64={version}"],text=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 if p.returncode:return False,p.stderr.strip()
 ok=False; arch=""; seen_version=""
 for line in p.stdout.splitlines():
  if line.startswith("Version: "):seen_version=line[9:]
  elif line.startswith("Architecture: "):arch=line[14:]
  elif not line.strip():
   if seen_version==version and arch in ("arm64","all"):ok=True
   arch=seen_version=""
 if seen_version==version and arch in ("arm64","all"):ok=True
 return ok,""

def main():
 a=argparse.ArgumentParser();a.add_argument("--reference",type=Path,required=True);a.add_argument("--apt-config",type=Path,required=True);a.add_argument("--snapshot",required=True);a.add_argument("--output-dir",type=Path,required=True);x=a.parse_args()
 d=json.loads(x.reference.read_text()); custom={(s["source"],s["source_version"]) for s in d["sources"] if s.get("custom_candidate")}
 rows=[]
 for p in sorted(d["packages"],key=lambda q:q["package"]):
  row={"package":p["package"],"amd64_version":p["version"],"amd64_architecture":p["architecture"],"source":p["source"],"source_version":p["source_version"],"arm64_package":"","arm64_version":"","status":"","reason":""}
  if p["architecture"]=="all":row.update(status="reuse-exact-all",arm64_package=p["package"],arm64_version=p["version"],reason="Architecture: all package is byte-reused from the AMD64 reference rootfs")
  elif p["package"] in CUSTOM_REPLACE:
   n,r=CUSTOM_REPLACE[p["package"]];row.update(status="custom-arch-replace",arm64_package=n,arm64_version=p["version"],reason=r)
  elif (p["source"],p["source_version"]) in custom:row.update(status="custom-rebuild",arm64_package=p["package"],arm64_version=p["version"],reason="exact +grm/+han source commit must be rebuilt for ARM64")
  elif p["package"] in OMIT:row.update(status="arch-omit",reason=OMIT[p["package"]])
  elif p["package"] in REPLACE:
   n,_,r=REPLACE[p["package"]];ok,e=available(x.apt_config,n,p["version"]);row.update(status="exact-arch-replace" if ok else "missing-arch-replacement",arm64_package=n,arm64_version=p["version"],reason=r if ok else (r+"; exact version not found: "+e))
  else:
   ok,e=available(x.apt_config,p["package"],p["version"]);row.update(status="exact-arm64" if ok else "missing-exact-arm64",arm64_package=p["package"],arm64_version=p["version"],reason="exact Debian ARM64 binary found" if ok else ("exact version absent from selected snapshot"+(": "+e if e else "")))
  rows.append(row)
 counts={}
 for r in rows:counts[r["status"]]=counts.get(r["status"],0)+1
 summary={"schema":1,"snapshot":x.snapshot,"package_count":len(rows),"status_counts":dict(sorted(counts.items())),"strict_unresolved_count":sum(v for k,v in counts.items() if k.startswith("missing-"))}
 x.output_dir.mkdir(parents=True,exist_ok=True)
 (x.output_dir/"debian-arm64-map.json").write_text(json.dumps({"summary":summary,"packages":rows},indent=2,ensure_ascii=False)+"\n")
 (x.output_dir/"debian-arm64-map-summary.json").write_text(json.dumps(summary,indent=2)+"\n")
 (x.output_dir/"debian-arm64-unresolved.json").write_text(json.dumps([r for r in rows if r["status"].startswith("missing-")],indent=2,ensure_ascii=False)+"\n")
 with (x.output_dir/"debian-arm64-map.tsv").open("w",newline="") as f:
  w=csv.DictWriter(f,fieldnames=list(rows[0]),delimiter="\t");w.writeheader();w.writerows(rows)
 print(json.dumps(summary,indent=2));return 0
if __name__=="__main__":raise SystemExit(main())
