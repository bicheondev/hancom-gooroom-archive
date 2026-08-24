#!/usr/bin/env python3
"""Lock exact AMD64 source versions to GitHub commits (fail closed)."""
import argparse, base64, csv, json, os, re, sys, time
from collections import defaultdict
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import Request, urlopen

API="https://api.github.com"
OWNERS=("hancomgooroom","hancom-io","gooroom")
ALIASES={"gtk+2.0":["gtk2"],"gtk+3.0":["gtk3"],
 "pam-gooroom":["libpam-gooroom-authenticator"],
 "linux-signed-amd64":["linux"],
 "qtbase-opensource-src":["qtbase5","qtbase"]}
HEAD=re.compile(r"^([^\s]+)\s+\(([^)]+)\)\s+")
SERIES3=re.compile(r"(?:^|[-_/])(?:hancom|gooroom)?-?3(?:[._-]|$)",re.I)

class GH:
 def __init__(self,token): self.token=token; self.cache={}; self.calls=0
 def get(self,path,missing=False):
  url=path if path.startswith("http") else API+path
  if url in self.cache:return self.cache[url]
  h={"Accept":"application/vnd.github+json","User-Agent":"hg-arm64-lock","X-GitHub-Api-Version":"2022-11-28"}
  if self.token:h["Authorization"]="Bearer "+self.token
  try:
   with urlopen(Request(url,headers=h),timeout=60) as r:data=json.load(r)
  except HTTPError as e:
   if missing and e.code==404:return None
   if e.code in (403,429):
    reset=e.headers.get("X-RateLimit-Reset")
    if reset and reset.isdigit():time.sleep(max(1,min(120,int(reset)-int(time.time())+1)));return self.get(path,missing)
   raise RuntimeError(f"GitHub API {e.code}: {url}: {e.read()[:300]!r}")
  self.calls+=1;self.cache[url]=data;return data
 def pages(self,path,limit=20):
  sep="&" if "?" in path else "?"
  for p in range(1,limit+1):
   rows=self.get(f"{path}{sep}per_page=100&page={p}")
   yield from rows
   if len(rows)<100:return
 def repos(self,owner):
  is_org=self.get(f"/orgs/{owner}",True)
  base=f"/orgs/{owner}/repos?type=public" if is_org else f"/users/{owner}/repos?type=public"
  return list(self.pages(base))
 def text(self,owner,repo,path,sha):
  x=self.get(f"/repos/{owner}/{repo}/contents/{quote(path,safe='/')}?ref={sha}",True)
  if not x or not isinstance(x,dict) or not isinstance(x.get("content"),str):return None
  return base64.b64decode(x["content"]).decode("utf-8","replace") if x.get("encoding")=="base64" else x["content"]

def head(text):
 if not text:return None
 for line in text.splitlines():
  if line.strip():
   m=HEAD.match(line);return m.groups() if m else None
 return None

def targets(path):
 d=json.loads(path.read_text()); by=defaultdict(list)
 for p in d["packages"]:by[(p["source"],p["source_version"])].append(p)
 out=[]
 for s in d["sources"]:
  if not s.get("custom_candidate"):continue
  ps=by[(s["source"],s["source_version"])]
  arches=sorted({p["architecture"] for p in ps})
  out.append({"source":s["source"],"version":s["source_version"],
   "packages":sorted(p["package"] for p in ps),"architectures":arches,
   "role":"reuse-all" if arches==["all"] else "rebuild-arm64"})
 return sorted(out,key=lambda x:x["source"])

def owner_order(t):
 return ("hancom-io","hancomgooroom","gooroom") if "han" in t["version"].lower() or t["source"].startswith("hancom") else ("gooroom","hancom-io","hancomgooroom")

def exact(gh,t,o,r,kind,name,sha,scope):
 h=head(gh.text(o,r,"debian/changelog",sha))
 if h!=(t["source"],t["version"]):return None
 c=gh.get(f"/repos/{o}/{r}/git/commits/{sha}")
 return {"owner":o,"repository":r,"repository_full_name":f"{o}/{r}","ref_kind":kind,
  "ref_name":name,"commit_sha":sha,"tree_sha":c["tree"]["sha"],
  "committer_date":c.get("committer",{}).get("date"),"match_scope":scope,
  "declared_source":h[0],"declared_version":h[1],"changelog_path":"debian/changelog"}

def refs(gh,o,r):
 b=gh.get(f"/repos/{o}/{r}/branches?per_page=100&page=1") or []
 tags=gh.get(f"/repos/{o}/{r}/tags?per_page=100&page=1") or []
 x=[("branch",z["name"],z["commit"]["sha"]) for z in b]
 x += [("tag",z["name"],z["commit"]["sha"]) for z in tags]
 return sorted(set(x),key=lambda z:(0 if z[0]=="branch" and SERIES3.search(z[1]) else 1,z[0],z[1]))

def history(gh,t,o,r,rr,max_commits):
 branches=[x for x in rr if x[0]=="branch"]
 branches.sort(key=lambda x:(0 if SERIES3.search(x[1]) else 1,0 if "3" in x[1] else 1,x[1]))
 found=[];seen=set();checked=0
 for _,name,_ in branches:
  endpoint=f"/repos/{o}/{r}/commits?sha={quote(name,safe='')}&path=debian/changelog"
  for c in gh.pages(endpoint,max(1,(max_commits+99)//100)):
   sha=c["sha"]
   if sha in seen:continue
   seen.add(sha);checked+=1
   m=exact(gh,t,o,r,"branch-history",name,sha,"historical-changelog")
   if m:found.append(m);break
   if checked>=max_commits:return found
  if found and not SERIES3.search(name):break
 return found

def resolve(gh,t,index,max_commits):
 names={t["source"].lower(),*(x.lower() for x in ALIASES.get(t["source"],[]))}
 repos=[]
 for o in OWNERS:
  for n in names:
   if n in index[o]:repos.append(index[o][n])
 res={"source":t["source"],"source_version":t["version"],"binary_packages":t["packages"],
  "binary_architectures":t["architectures"],"role":t["role"],"searched_repository_names":sorted(names),
  "repositories_found":[x["full_name"] for x in repos],"status":"unresolved-repository" if not repos else "unresolved-version",
  "selected":None,"exact_matches":[]}
 if not repos:return res
 matches=[];allrefs={}
 for repo in repos:
  o=repo["owner"]["login"];r=repo["name"];rr=refs(gh,o,r);allrefs[(o,r)]=rr
  for kind,name,sha in rr:
   m=exact(gh,t,o,r,kind,name,sha,"ref-tip")
   if m:matches.append(m)
 if not matches:
  rank={o:i for i,o in enumerate(owner_order(t))}
  for repo in sorted(repos,key=lambda x:rank[x["owner"]["login"]]):
   o=repo["owner"]["login"];r=repo["name"]
   matches+=history(gh,t,o,r,allrefs[(o,r)],max_commits)
   if matches and rank[o]==0:break
 uniq={(m["repository_full_name"],m["commit_sha"]):m for m in matches}
 matches=list(uniq.values());res["exact_matches"]=sorted(matches,key=lambda m:(m["owner"],m["ref_name"],m["commit_sha"]))
 if not matches:return res
 order={o:i for i,o in enumerate(owner_order(t))};best=min(order[m["owner"]] for m in matches)
 auth=[m for m in matches if order[m["owner"]]==best]
 def cat(m):return (0 if m["ref_kind"]=="tag" else 1 if SERIES3.search(m["ref_name"]) else 2 if m["ref_kind"]=="branch" else 3,0 if m["match_scope"]=="ref-tip" else 1)
 bestcat=min(cat(m) for m in auth);auth=[m for m in auth if cat(m)==bestcat]
 if len({m["tree_sha"] for m in auth})!=1:res["status"]="ambiguous-exact-version";return res
 chosen=sorted(auth,key=lambda m:(m.get("committer_date") or "",m["commit_sha"]),reverse=True)[0].copy()
 chosen["source_archive"]=f"https://github.com/{chosen['repository_full_name']}/archive/{chosen['commit_sha']}.tar.gz"
 res["selected"]=chosen;res["status"]="resolved";return res

def write(out,rows,calls):
 out.mkdir(parents=True,exist_ok=True);bad=[x for x in rows if x["status"]!="resolved"]
 s={"schema":1,"policy":"exact-debian-changelog-version","source_target_count":len(rows),
  "resolved_count":len(rows)-len(bad),"unresolved_count":len(bad),
  "rebuild_target_count":sum(x["role"]=="rebuild-arm64" for x in rows),
  "rebuild_unresolved_count":sum(x["role"]=="rebuild-arm64" for x in bad),
  "reuse_all_target_count":sum(x["role"]=="reuse-all" for x in rows),"github_api_request_count":calls}
 (out/"source-lock.json").write_text(json.dumps({"summary":s,"sources":rows},indent=2,ensure_ascii=False)+"\n")
 (out/"source-lock-summary.json").write_text(json.dumps(s,indent=2)+"\n")
 (out/"unresolved-sources.json").write_text(json.dumps(bad,indent=2,ensure_ascii=False)+"\n")
 with (out/"source-lock.tsv").open("w",newline="") as f:
  fields="source source_version role status binary_architectures repository_full_name ref_kind ref_name commit_sha tree_sha match_scope".split();w=csv.DictWriter(f,fields,delimiter="\t");w.writeheader()
  for x in rows:
   m=x["selected"] or {};w.writerow({"source":x["source"],"source_version":x["source_version"],"role":x["role"],"status":x["status"],"binary_architectures":",".join(x["binary_architectures"]),**{k:m.get(k,"") for k in fields[5:]}})
 return s

def main():
 a=argparse.ArgumentParser();a.add_argument("--reference",type=Path,required=True);a.add_argument("--output-dir",type=Path,required=True);a.add_argument("--max-changelog-commits",type=int,default=300);a.add_argument("--fail-on-rebuild-unresolved",action="store_true");x=a.parse_args()
 gh=GH(os.getenv("GITHUB_TOKEN"));idx={}
 for o in OWNERS:
  rs=gh.repos(o);idx[o]={r["name"].lower():r for r in rs};print(o,len(rs),file=sys.stderr)
 ts=targets(x.reference);rows=[]
 for i,t in enumerate(ts,1):print(f"[{i}/{len(ts)}] {t['source']} {t['version']} {t['role']}",file=sys.stderr);rows.append(resolve(gh,t,idx,x.max_changelog_commits))
 s=write(x.output_dir,rows,gh.calls);print(json.dumps(s,indent=2));return 2 if x.fail_on_rebuild_unresolved and s["rebuild_unresolved_count"] else 0
if __name__=="__main__":raise SystemExit(main())
