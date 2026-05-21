# 🔓 OWASP MSTG UnCrackable Level 3 — Writeup

> **Challenge officiel** : [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mastg)  
> **Objectif** : Trouver le code secret caché dans une application Android protégée  
> **Difficulté** : ⭐⭐⭐ Avancé  

---

## 📋 Table des matières

1. [Présentation du challenge](#-présentation-du-challenge)
2. [Outils utilisés](#-outils-utilisés)
3. [Analyse statique du code Java](#-analyse-statique-du-code-java)
4. [Protections détectées](#-protections-détectées)
5. [Patch Smali — Bypass des protections](#-patch-smali--bypass-des-protections)
6. [Recompilation et signature](#-recompilation-et-signature)
7. [Installation et test](#-installation-et-test)
8. [Analyse de libfoo.so — Extraction du flag](#-analyse-de-libfooso--extraction-du-flag)
9. [Résumé de la solution](#-résumé-de-la-solution)

---

## 🎯 Présentation du challenge

UnCrackable Level 3 est le challenge Android le plus difficile de la série OWASP MSTG.  
L'application demande un **code secret** à l'utilisateur. Le but est de retrouver ce code en contournant toutes les protections mises en place.

```
Package : owasp.mstg.uncrackable3
Activité principale : sg.vantagepoint.uncrackable3.MainActivity
Lib native : libfoo.so
Clé XOR : "pizzapizzapizzapizzapizz" (24 caractères)
```

---

## 🛠 Outils utilisés

| Outil | Version | Usage |
|-------|---------|-------|
| **apktool** | 3.0.2 | Décompilation / Recompilation APK |
| **jadx** | latest | Décompilation Java |
| **apksigner** | 36.0.0 (build-tools) | Signature APK |
| **adb** | SDK Platform Tools | Installation sur émulateur |
| **Ghidra / IDA** | — | Analyse de libfoo.so |
| **Python 3** | — | Déchiffrement XOR |
| **VS Code** | — | Édition du Smali |

---

## 🔍 Analyse statique du code Java

### Décompilation avec apktool

```powershell
apktool d UnCrackable-Level3.apk -o uncrackable3
```
<img width="1153" height="388" alt="image" src="https://github.com/user-attachments/assets/934beb6a-f06b-48c1-889c-0e6019b25fa1" />


**Résultat :**
```
I: Using Apktool 3.0.2 on UnCrackable-Level3.apk with 4 threads
I: Baksmaling classes.dex...
I: Built apk into: uncrackable3/
```

### Lecture du code source (jadx)

Le fichier `MainActivity.java` décompilé révèle :

```java
private static final String xorkey = "pizzapizzapizzapizzapizz";
private CodeCheck check;
static int tampered = 0;

protected void onCreate(Bundle bundle) {
    verifyLibs();               // Vérifie les CRC des libs
    init(xorkey.getBytes());    // Initialise la lib native avec la clé XOR
    // ...
    if (RootDetection.checkRoot1() || RootDetection.checkRoot2() || 
        RootDetection.checkRoot3() || IntegrityCheck.isDebuggable(...) || 
        tampered != 0) {
        showDialog("Rooting or tampering detected.");
    }
}

public void verify(View view) {
    String input = editText.getText().toString();
    if (this.check.check_code(input)) {
        // SUCCESS !
    }
}
```

**Points clés identifiés :**
- La clé XOR `"pizzapizzapizzapizzapizz"` est passée à la lib native via `init()`
- La vérification du secret est faite dans `CodeCheck.check_code()` — **dans la lib native**
- Variable `tampered` surveillée en permanence

---

## 🛡 Protections détectées

| Protection | Mécanisme | Impact |
|-----------|-----------|--------|
| **Root Detection** | `checkRoot1/2/3()` | Quitte l'app si root détecté |
| **Anti-Debug** | Thread AsyncTask en boucle | Quitte si debugger attaché |
| **Integrity Check** | CRC de `libfoo.so` + `classes.dex` | Met `tampered = 31337` |
| **Native Check** | `baz()` vérifie le CRC de classes.dex | Met `tampered = 31337` |
| **Debuggable Check** | `IntegrityCheck.isDebuggable()` | Quitte si app debuggable |

---

## 🔧 Patch Smali — Bypass des protections

### Fichier à modifier

```
uncrackable3/smali/sg/vantagepoint/uncrackable3/MainActivity.smali
```

### Patch 1 — Neutraliser `showDialog()`

**Avant :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    .line 38
    new-instance v0, Landroid/app/AlertDialog$Builder;
    ; ... tout le code du popup ...
    return-void
.end method
```

**Après :**
```smali
.method private showDialog(Ljava/lang/String;)V
    .locals 3
    return-void
.end method
```

> ✅ Tout appel à `showDialog()` devient instantanément un no-op.

---

### Patch 2 — Bypasser le bloc root/tamper dans `onCreate()`

**Avant :**
```smali
    :cond_0
    const-string v0, "Rooting or tampering detected."
    .line 127
    invoke-direct {p0, v0}, Lsg/vantagepoint/uncrackable3/MainActivity;->showDialog(Ljava/lang/String;)V
    .line 130
    :cond_1
```

**Après :**
```smali
    :cond_0
    goto :cond_1
    .line 130
    :cond_1
```

> ✅ Peu importe si root/tamper est détecté, on saute directement à `:cond_1`.

---

## 📦 Recompilation et signature

### Recompilation

```powershell
apktool b uncrackable3 -o UnCrackable-Level3-patched.apk
```

**Résultat :**
```
I: Smaling smali folder into classes.dex...
I: Building resources with aapt2...
I: Building apk file...
I: Built apk into: UnCrackable-Level3-patched.apk
```

### Localiser apksigner

```powershell
Get-ChildItem -Path "C:\Users\lenovo\AppData\Local\Android" -Recurse -Filter "apksigner.bat" | Select-Object FullName
```

```
C:\Users\lenovo\AppData\Local\Android\Sdk\build-tools\36.0.0\apksigner.bat
```

### Signature avec le debug keystore

```powershell
& "C:\Users\lenovo\AppData\Local\Android\Sdk\build-tools\36.0.0\apksigner.bat" `
  sign --ks "C:\Users\lenovo\.android\debug.keystore" `
  --ks-pass pass:android `
  UnCrackable-Level3-patched.apk
```

---

## 📲 Installation et test

### Désinstaller l'ancienne version (si présente)

```powershell
adb uninstall owasp.mstg.uncrackable3
# Success
```

### Installer l'APK patché

```powershell
adb install UnCrackable-Level3-patched.apk
# Performing Streamed Install
# Success
```

### Lancer l'application

```powershell
adb shell monkey -p owasp.mstg.uncrackable3 -c android.intent.category.LAUNCHER 1
# Events injected: 1
```
<img width="717" height="301" alt="image" src="https://github.com/user-attachments/assets/ab627b80-d52c-4b88-8494-864bac848c5f" />


> ✅ L'app s'ouvre **sans popup** "Rooting or tampering detected."

---

## 🔬 Analyse de libfoo.so — Extraction du flag

### Structure de libfoo.so

La lib native contient :

| Fonction | Rôle |
|----------|------|
| `Java_..._MainActivity_init` | Reçoit la clé XOR, initialise le buffer secret |
| `Java_..._MainActivity_baz` | Retourne le CRC attendu de classes.dex |
| `Java_..._CodeCheck_check_1code` | Compare l'input utilisateur au secret déchiffré |

### Méthode d'extraction

La fonction `init()` reçoit `"pizzapizzapizzapizzapizz"` et XOR ce buffer avec le secret stocké dans la lib.

**Avec Ghidra :**
1. Importer `uncrackable3/lib/x86/libfoo.so`
2. Lancer l'analyse automatique
3. Dans Symbol Tree → chercher `check_code`
4. Le décompilateur montre un buffer de bytes chiffrés

**Script Python pour déchiffrer :**

```python
key = b"pizzapizzapizzapizzapizz"

# Bytes trouvés dans libfoo.so (buffer chiffré)
encrypted = bytes([...])  # à remplacer par les bytes de Ghidra

flag = bytes([encrypted[i] ^ key[i % len(key)] for i in range(len(encrypted))])
print("[+] Flag :", flag.decode())
```

### Alternative — Hook Frida

```javascript
// hook.js
Java.perform(function() {
    var CodeCheck = Java.use("sg.vantagepoint.uncrackable3.CodeCheck");
    CodeCheck.check_code.implementation = function(input) {
        console.log("[*] Input testé : " + input);
        var result = this.check_code(input);
        console.log("[*] Résultat : " + result);
        return result;
    };
});
```

```powershell
frida -U -f owasp.mstg.uncrackable3 -l hook.js --no-pause
```

---

## 📊 Résumé de la solution

```
┌─────────────────────────────────────────────────────────┐
│              FLOW DE RÉSOLUTION                         │
├─────────────────────────────────────────────────────────┤
│  1. apktool d  →  Décompiler l'APK                      │
│  2. jadx       →  Analyser MainActivity.java            │
│  3. Smali      →  Patcher showDialog() + root check     │
│  4. apktool b  →  Recompiler                            │
│  5. apksigner  →  Signer avec debug.keystore            │
│  6. adb        →  Installer sur émulateur               │
│  7. Ghidra     →  Analyser libfoo.so                    │
│  8. Python XOR →  Déchiffrer le flag                    │
└─────────────────────────────────────────────────────────┘
```

### Protections bypAssées ✅

- [x] Root Detection (checkRoot1/2/3)
- [x] Tamper Detection (CRC libs + classes.dex)
- [x] showDialog neutralisée
- [ ] Anti-Debug (thread AsyncTask) — à bypasser via Frida
- [ ] Logique native check_code — à analyser dans Ghidra

---

## 📚 Références

- [OWASP MSTG GitHub](https://github.com/OWASP/owasp-mastg)
- [apktool Documentation](https://apktool.org/)
- [Frida Documentation](https://frida.re/docs/)
- [Ghidra NSA](https://ghidra-sre.org/)

---

*Writeup réalisé dans un cadre éducatif — OWASP Mobile Security Testing Guide*
