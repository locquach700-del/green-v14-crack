import os, glob, sys, re

print("[*] GREEN V14 crack")

# strip unknown manifest attrs
mf = "green/AndroidManifest.xml"
if os.path.isfile(mf):
    with open(mf, encoding="utf-8", errors="ignore") as f:
        m = f.read()
    m2 = re.sub(r'\s*android:pageSizeCompat="[^"]*"', '', m)
    m2 = re.sub(r'\s*android:[a-zA-Z0-9_]*Compat="[^"]*"', '', m2)
    if m2 != m:
        open(mf, "w", encoding="utf-8").write(m2)
        print("[OK] manifest cleaned")

def replace_method(path, sig, body):
    with open(path) as f:
        c = f.read()
    start = c.find(sig)
    if start == -1:
        return False
    nextm = c.find("\n.method ", start + 10)
    if nextm == -1:
        nextm = len(c)
    end = c.rfind(".end method", start, nextm)
    if end == -1:
        return False
    open(path, "w").write(c[:start] + body + c[end + len(".end method"):])
    return True

# GreenApi.validate -> always success Result (expires=0, force=false, empty link)
for pattern in ["green/smali*/**/GreenApi.smali", "green/smali/**/GreenApi.smali"]:
    for p in glob.glob(pattern, recursive=True):
        body = """.method public static validate(Ljava/lang/String;Z)Lcom/xyz/app/GreenApi$Result;
    .registers 3
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation

    new-instance v0, Lcom/xyz/app/GreenApi$Result;
    invoke-direct {v0}, Lcom/xyz/app/GreenApi$Result;-><init>()V
    const-wide/16 v1, 0x0
    iput-wide v1, v0, Lcom/xyz/app/GreenApi$Result;->expires:J
    const/4 v1, 0x0
    iput-boolean v1, v0, Lcom/xyz/app/GreenApi$Result;->force:Z
    const-string v1, ""
    iput-object v1, v0, Lcom/xyz/app/GreenApi$Result;->link:Ljava/lang/String;
    return-object v0
.end method
"""
        if replace_method(p, ".method public static validate(Ljava/lang/String;Z)Lcom/xyz/app/GreenApi$Result;", body):
            print("[OK] GreenApi.validate", p)

        body2 = """.method public static consume(Lcom/xyz/app/GreenApi$Result;)V
    .registers 1
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation
    return-void
.end method
"""
        if replace_method(p, ".method public static consume(Lcom/xyz/app/GreenApi$Result;)V", body2):
            print("[OK] GreenApi.consume", p)

        body3 = """.method public static log(Landroid/content/Context;Ljava/lang/String;)V
    .registers 2
    .annotation system Ldalvik/annotation/Throws;
        value = {
            Ljava/lang/Exception;
        }
    .end annotation
    return-void
.end method
"""
        if replace_method(p, ".method public static log(Landroid/content/Context;Ljava/lang/String;)V", body3):
            print("[OK] GreenApi.log", p)

# IntegrityVerifier if present
for pattern in ["green/smali*/**/IntegrityVerifier.smali", "green/smali/**/IntegrityVerifier.smali"]:
    for p in glob.glob(pattern, recursive=True):
        body = """.method static verify(Ljava/io/File;[[BLjava/lang/String;)Z
    .registers 3
    const/4 v0, 0x1
    return v0
.end method
"""
        if replace_method(p, ".method static verify(Ljava/io/File;[[BLjava/lang/String;)Z", body):
            print("[OK] IntegrityVerifier", p)

# ProtectedApplication
for pattern in ["green/smali*/**/ProtectedApplication.smali", "green/smali/**/ProtectedApplication.smali"]:
    for p in glob.glob(pattern, recursive=True):
        with open(p) as f:
            c = f.read()
        changed = False
        for sig, body in [
(".method public static trusted(Landroid/content/Context;)Z",
".method public static trusted(Landroid/content/Context;)Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method\n"),
(".method public static require(Landroid/app/Activity;)Z",
".method public static require(Landroid/app/Activity;)Z\n    .registers 1\n    const/4 v0, 0x1\n    return v0\n.end method\n")
]:
            start = c.find(sig)
            if start != -1:
                nextm = c.find("\n.method ", start + 10)
                if nextm == -1: nextm = len(c)
                end = c.rfind(".end method", start, nextm)
                c = c[:start] + body + c[end+len(".end method"):]
                changed = True
        if changed:
            open(p,"w").write(c)
            print("[OK] ProtectedApplication", p)

# SecurityCheck - neuter emulator kill if any public check returns boolean
for pattern in ["green/smali*/**/SecurityCheck.smali", "green/smali/**/SecurityCheck.smali"]:
    for p in glob.glob(pattern, recursive=True):
        with open(p) as f:
            c = f.read()
        # force isEmulator / isDebugger / detect methods to false
        for name in ["isEmulator", "isDebuggerConnected", "detect", "check", "isSuspicious", "shouldBlock"]:
            # generic: methods returning Z that contain these names
            pass
        # Replace common return true for emulator checks - safer: find .method public static isEmulator
        for sig in [
            ".method public static isEmulator(Landroid/content/Context;)Z",
            ".method public static isEmulator()Z",
            ".method public static detect(Landroid/content/Context;)Z",
            ".method public static check(Landroid/content/Context;)Z",
        ]:
            start = c.find(sig)
            if start != -1:
                nextm = c.find("\n.method ", start + 10)
                if nextm == -1: nextm = len(c)
                end = c.rfind(".end method", start, nextm)
                body = sig + "\n    .registers 1\n    const/4 v0, 0x0\n    return v0\n.end method\n"
                c = c[:start] + body + c[end+len(".end method"):]
                print("[OK] SecurityCheck", sig.split()[-1], p)
        open(p,"w").write(c)

print("[*] Done")
