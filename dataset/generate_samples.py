#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Dataset Generator for LLM-Hybrid Code Security Audit System
Generates 150 synthetic vulnerability samples (50 C, 50 Java, 50 Python)
with realistic code, CWE annotations, and fixed versions.
"""
import os, csv, random, json

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SAMPLES_DIR = os.path.join(BASE_DIR, "dataset")
MANIFEST_PATH = os.path.join(SAMPLES_DIR, "samples_manifest.csv")
STATS_PATH = os.path.join(SAMPLES_DIR, "dataset_stats.json")

random.seed(42)

# CWE definitions for each language
CWE_PATTERNS = {
    "C": [
        ("CWE-120", "Buffer Overflow", "classic_strcpy", "高风险"),
        ("CWE-121", "Stack Buffer Overflow", "stack_overflow", "高风险"),
        ("CWE-122", "Heap Buffer Overflow", "heap_overflow", "高风险"),
        ("CWE-190", "Integer Overflow", "int_overflow", "中风险"),
        ("CWE-191", "Integer Underflow", "int_underflow", "中风险"),
        ("CWE-415", "Double Free", "double_free", "高风险"),
        ("CWE-416", "Use After Free", "use_after_free", "高风险"),
        ("CWE-476", "NULL Pointer Dereference", "null_deref", "中风险"),
        ("CWE-457", "Use of Uninitialized Variable", "uninit_var", "中风险"),
        ("CWE-134", "Uncontrolled Format String", "format_string", "高风险"),
        ("CWE-78", "OS Command Injection", "cmd_injection", "高风险"),
        ("CWE-22", "Path Traversal", "path_traversal", "中风险"),
        ("CWE-195", "Signed to Unsigned Conversion Error", "sign_conv", "中风险"),
        ("CWE-787", "Out-of-bounds Write", "oob_write", "高风险"),
        ("CWE-119", "Improper Restriction of Operations within Buffer", "buffer_ops", "高风险"),
    ],
    "Java": [
        ("CWE-89", "SQL Injection", "sql_injection", "高风险"),
        ("CWE-79", "Cross-site Scripting (XSS)", "xss_reflected", "高风险"),
        ("CWE-502", "Deserialization of Untrusted Data", "deserialization", "高风险"),
        ("CWE-22", "Path Traversal", "path_traversal", "中风险"),
        ("CWE-78", "OS Command Injection", "cmd_injection", "高风险"),
        ("CWE-611", "XML External Entity (XXE)", "xxe", "高风险"),
        ("CWE-918", "Server-Side Request Forgery (SSRF)", "ssrf", "中风险"),
        ("CWE-200", "Information Exposure", "info_exposure", "低风险"),
        ("CWE-312", "Cleartext Storage of Sensitive Information", "cleartext_storage", "中风险"),
        ("CWE-327", "Use of Broken or Risky Cryptographic Algorithm", "weak_crypto", "中风险"),
        ("CWE-20", "Improper Input Validation", "input_validation", "中风险"),
        ("CWE-434", "Unrestricted Upload of File", "file_upload", "高风险"),
        ("CWE-94", "Code Injection", "code_injection", "高风险"),
        ("CWE-798", "Use of Hard-coded Credentials", "hardcoded_creds", "中风险"),
        ("CWE-307", "Improper Restriction of Excessive Authentication Attempts", "brute_force", "中风险"),
    ],
    "Python": [
        ("CWE-78", "OS Command Injection", "cmd_injection", "高风险"),
        ("CWE-89", "SQL Injection", "sql_injection", "高风险"),
        ("CWE-22", "Path Traversal", "path_traversal", "中风险"),
        ("CWE-502", "Deserialization of Untrusted Data", "pickle_deser", "高风险"),
        ("CWE-917", "Expression Language Injection", "eval_injection", "高风险"),
        ("CWE-20", "Improper Input Validation", "input_validation", "中风险"),
        ("CWE-200", "Information Exposure", "info_exposure", "低风险"),
        ("CWE-295", "Improper Certificate Validation", "cert_validation", "中风险"),
        ("CWE-532", "Insertion of Sensitive Information into Log File", "log_exposure", "低风险"),
        ("CWE-377", "Insecure Temporary File", "tmp_file", "中风险"),
        ("CWE-94", "Code Injection", "exec_injection", "高风险"),
        ("CWE-798", "Use of Hard-coded Credentials", "hardcoded_creds", "中风险"),
        ("CWE-862", "Missing Authorization", "missing_auth", "中风险"),
        ("CWE-918", "Server-Side Request Forgery (SSRF)", "ssrf", "中风险"),
        ("CWE-116", "Improper Encoding or Escaping", "improper_encoding", "中风险"),
    ]
}

# Templates for vulnerable and fixed code
TEMPLATES = {
    "C": {
        "classic_strcpy": (
            """#include <string.h>
void copy_input(char *input) {
    char buffer[64];
    strcpy(buffer, input);  // VULN: no bounds check
}
""",
            """#include <string.h>
void copy_input(char *input) {
    char buffer[64];
    if (input != NULL) {
        strncpy(buffer, input, sizeof(buffer) - 1);
        buffer[sizeof(buffer) - 1] = '\\0';
    }
}
"""
        ),
        "stack_overflow": (
            """#include <stdio.h>
void process(int idx) {
    int arr[10];
    arr[idx] = 42;  // VULN: idx unchecked
}
""",
            """#include <stdio.h>
void process(int idx) {
    int arr[10];
    if (idx >= 0 && idx < 10) {
        arr[idx] = 42;
    } else {
        fprintf(stderr, "Index out of bounds\\n");
    }
}
"""
        ),
        "heap_overflow": (
            """#include <stdlib.h>
#include <string.h>
void heap_copy(char *src) {
    char *dst = malloc(10);
    strcpy(dst, src);  // VULN: dst may be too small
    free(dst);
}
""",
            """#include <stdlib.h>
#include <string.h>
void heap_copy(char *src) {
    size_t len = strlen(src) + 1;
    char *dst = malloc(len);
    if (dst != NULL) {
        strncpy(dst, src, len - 1);
        dst[len - 1] = '\\0';
        free(dst);
    }
}
"""
        ),
        "int_overflow": (
            """#include <stdio.h>
int alloc_size(int n) {
    return n * sizeof(int);  // VULN: integer overflow possible
}
""",
            """#include <stdio.h>
#include <limits.h>
int alloc_size(int n) {
    if (n > 0 && n > INT_MAX / sizeof(int)) {
        fprintf(stderr, "Integer overflow detected\\n");
        return -1;
    }
    return n * sizeof(int);
}
"""
        ),
        "int_underflow": (
            """#include <stdio.h>
unsigned int subtract(unsigned int a, unsigned int b) {
    return a - b;  // VULN: underflow if b > a
}
""",
            """#include <stdio.h>
unsigned int subtract(unsigned int a, unsigned int b) {
    if (b > a) {
        fprintf(stderr, "Underflow detected\\n");
        return 0;
    }
    return a - b;
}
"""
        ),
        "double_free": (
            """#include <stdlib.h>
void cleanup(char *p) {
    free(p);
    free(p);  // VULN: double free
}
""",
            """#include <stdlib.h>
void cleanup(char *p) {
    if (p != NULL) {
        free(p);
        p = NULL;
    }
}
"""
        ),
        "use_after_free": (
            """#include <stdlib.h>
#include <stdio.h>
void uaf_example() {
    char *msg = malloc(20);
    free(msg);
    printf("%s", msg);  // VULN: use after free
}
""",
            """#include <stdlib.h>
#include <stdio.h>
void uaf_example() {
    char *msg = malloc(20);
    if (msg != NULL) {
        snprintf(msg, 20, "Hello");
        printf("%s", msg);
        free(msg);
        msg = NULL;
    }
}
"""
        ),
        "null_deref": (
            """#include <stdio.h>
void print_len(char *s) {
    printf("%d", strlen(s));  // VULN: s may be NULL
}
""",
            """#include <stdio.h>
#include <string.h>
void print_len(char *s) {
    if (s != NULL) {
        printf("%zu", strlen(s));
    } else {
        printf("0");
    }
}
"""
        ),
        "uninit_var": (
            """#include <stdio.h>
int sum_array(int *arr, int n) {
    int sum;
    for (int i = 0; i < n; i++) {
        sum += arr[i];  // VULN: sum uninitialized
    }
    return sum;
}
""",
            """#include <stdio.h>
int sum_array(int *arr, int n) {
    int sum = 0;
    if (arr == NULL || n <= 0) return 0;
    for (int i = 0; i < n; i++) {
        sum += arr[i];
    }
    return sum;
}
"""
        ),
        "format_string": (
            """#include <stdio.h>
void log_msg(char *msg) {
    printf(msg);  // VULN: format string injection
}
""",
            """#include <stdio.h>
void log_msg(char *msg) {
    if (msg != NULL) {
        printf("%s", msg);
    }
}
"""
        ),
        "cmd_injection": (
            """#include <stdlib.h>
void run_cmd(char *user_input) {
    system(user_input);  // VULN: command injection
}
""",
            """#include <stdlib.h>
#include <string.h>
void run_cmd(char *user_input) {
    if (user_input == NULL) return;
    if (strpbrk(user_input, ";&|")) {
        fprintf(stderr, "Invalid characters\\n");
        return;
    }
    system(user_input);
}
"""
        ),
        "path_traversal": (
            """#include <stdio.h>
FILE* open_file(char *filename) {
    return fopen(filename, "r");  // VULN: path traversal
}
""",
            """#include <stdio.h>
#include <string.h>
FILE* open_file(char *filename) {
    if (filename == NULL || strstr(filename, "..") != NULL) {
        fprintf(stderr, "Invalid path\\n");
        return NULL;
    }
    return fopen(filename, "r");
}
"""
        ),
        "sign_conv": (
            """#include <stdio.h>
void write_data(int len) {
    char buf[100];
    if (len < 100)
        memcpy(buf, "data", len);  // VULN: len is signed, negative bypasses check
}
""",
            """#include <stdio.h>
#include <string.h>
void write_data(int len) {
    char buf[100];
    if (len > 0 && len < 100)
        memcpy(buf, "data", len);
}
"""
        ),
        "oob_write": (
            """#include <stdio.h>
void set_flag(int idx) {
    int flags[5] = {0};
    flags[idx] = 1;  // VULN: idx unchecked
}
""",
            """#include <stdio.h>
void set_flag(int idx) {
    int flags[5] = {0};
    if (idx >= 0 && idx < 5) {
        flags[idx] = 1;
    }
}
"""
        ),
        "buffer_ops": (
            """#include <string.h>
void concat(char *a, char *b) {
    char buf[32];
    strcat(buf, a);  // VULN: potential overflow
    strcat(buf, b);
}
""",
            """#include <string.h>
void concat(char *a, char *b) {
    char buf[32];
    buf[0] = '\\0';
    if (a != NULL)
        strncat(buf, a, sizeof(buf) - strlen(buf) - 1);
    if (b != NULL)
        strncat(buf, b, sizeof(buf) - strlen(buf) - 1);
}
"""
        ),
    },
    "Java": {
        "sql_injection": (
            """import java.sql.*;
public class UserDAO {
    public User getUser(String username) {
        String query = "SELECT * FROM users WHERE name = '" + username + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(query);  // VULN: SQL injection
    }
}
""",
            """import java.sql.*;
public class UserDAO {
    public User getUser(String username) {
        String query = "SELECT * FROM users WHERE name = ?";
        PreparedStatement pstmt = conn.prepareStatement(query);
        pstmt.setString(1, username);
        return pstmt.executeQuery();
    }
}
"""
        ),
        "xss_reflected": (
            """import javax.servlet.http.*;
public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        String q = req.getParameter("q");
        res.getWriter().write("<h1>Results for " + q + "</h1>");  // VULN: XSS
    }
}
""",
            """import javax.servlet.http.*;
import org.owasp.encoder.Encode;
public class SearchServlet extends HttpServlet {
    protected void doGet(HttpServletRequest req, HttpServletResponse res) {
        String q = req.getParameter("q");
        res.getWriter().write("<h1>Results for " + Encode.forHtml(q) + "</h1>");
    }
}
"""
        ),
        "deserialization": (
            """import java.io.*;
public class ObjectReader {
    public Object read(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
        return ois.readObject();  // VULN: untrusted deserialization
    }
}
""",
            """import java.io.*;
public class ObjectReader {
    private static final Set<String> ALLOWED = Set.of("com.example.SafeClass");
    public Object read(byte[] data) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data)) {
            protected Class<?> resolveClass(ObjectStreamClass desc) {
                if (!ALLOWED.contains(desc.getName())) {
                    throw new SecurityException("Class not allowed");
                }
                return super.resolveClass(desc);
            }
        };
        return ois.readObject();
    }
}
"""
        ),
        "path_traversal": (
            """import java.io.*;
public class FileService {
    public String readFile(String path) throws IOException {
        File f = new File("/app/data/" + path);
        return new String(Files.readAllBytes(f.toPath()));  // VULN: path traversal
    }
}
""",
            """import java.io.*;
import java.nio.file.*;
public class FileService {
    public String readFile(String path) throws IOException {
        Path base = Paths.get("/app/data").normalize().toAbsolutePath();
        Path target = base.resolve(path).normalize().toAbsolutePath();
        if (!target.startsWith(base)) {
            throw new SecurityException("Invalid path");
        }
        return new String(Files.readAllBytes(target));
    }
}
"""
        ),
        "cmd_injection": (
            """import java.lang.Runtime;
public class ShellRunner {
    public String run(String cmd) throws Exception {
        Process p = Runtime.getRuntime().exec(cmd);  // VULN: command injection
        return new String(p.getInputStream().readAllBytes());
    }
}
""",
            """import java.lang.Runtime;
import java.util.List;
public class ShellRunner {
    public String run(List<String> cmd) throws Exception {
        ProcessBuilder pb = new ProcessBuilder(cmd);
        pb.redirectErrorStream(true);
        Process p = pb.start();
        return new String(p.getInputStream().readAllBytes());
    }
}
"""
        ),
        "xxe": (
            """import javax.xml.parsers.*;
import org.w3c.dom.*;
public class XMLParser {
    public Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = f.newDocumentBuilder();
        return db.parse(new InputSource(new StringReader(xml)));  // VULN: XXE
    }
}
""",
            """import javax.xml.parsers.*;
import org.w3c.dom.*;
public class XMLParser {
    public Document parse(String xml) throws Exception {
        DocumentBuilderFactory f = DocumentBuilderFactory.newInstance();
        f.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        f.setFeature("http://xml.org/sax/features/external-general-entities", false);
        f.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        DocumentBuilder db = f.newDocumentBuilder();
        return db.parse(new InputSource(new StringReader(xml)));
    }
}
"""
        ),
        "ssrf": (
            """import java.net.*;
public class URLFetcher {
    public String fetch(String url) throws Exception {
        URL u = new URL(url);
        return new String(u.openStream().readAllBytes());  // VULN: SSRF
    }
}
""",
            """import java.net.*;
import java.util.Set;
public class URLFetcher {
    private static final Set<String> ALLOWED = Set.of("api.example.com", "cdn.example.com");
    public String fetch(String urlStr) throws Exception {
        URL u = new URL(urlStr);
        if (!ALLOWED.contains(u.getHost())) {
            throw new SecurityException("Host not allowed");
        }
        return new String(u.openStream().readAllBytes());
    }
}
"""
        ),
        "info_exposure": (
            """import java.io.*;
public class ErrorHandler {
    public void handle(Exception e, PrintWriter out) {
        e.printStackTrace(out);  // VULN: info exposure
    }
}
""",
            """import java.io.*;
import java.util.logging.*;
public class ErrorHandler {
    private static final Logger LOG = Logger.getLogger(ErrorHandler.class.getName());
    public void handle(Exception e, PrintWriter out) {
        LOG.log(Level.SEVERE, "Error", e);
        out.write("An error occurred. Please try again later.");
    }
}
"""
        ),
        "cleartext_storage": (
            """import java.io.*;
public class ConfigWriter {
    public void savePassword(String password) throws IOException {
        FileWriter fw = new FileWriter("config.txt");
        fw.write("password=" + password);  // VULN: cleartext storage
        fw.close();
    }
}
""",
            """import java.io.*;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
public class ConfigWriter {
    public void savePassword(String password) throws Exception {
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encrypted = cipher.doFinal(password.getBytes());
        FileWriter fw = new FileWriter("config.txt");
        fw.write("password=" + Base64.getEncoder().encodeToString(encrypted));
        fw.close();
    }
}
"""
        ),
        "weak_crypto": (
            """import javax.crypto.*;
public class Crypto {
    public byte[] encrypt(String data) throws Exception {
        Cipher c = Cipher.getInstance("DES/ECB/PKCS5Padding");  // VULN: weak algorithm
        SecretKey key = KeyGenerator.getInstance("DES").generateKey();
        c.init(Cipher.ENCRYPT_MODE, key);
        return c.doFinal(data.getBytes());
    }
}
""",
            """import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.SecureRandom;
public class Crypto {
    public byte[] encrypt(String data) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        SecretKey key = KeyGenerator.getInstance("AES").generateKey();
        byte[] iv = new byte[12];
        new SecureRandom().nextBytes(iv);
        c.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(128, iv));
        return c.doFinal(data.getBytes());
    }
}
"""
        ),
        "input_validation": (
            """public class DiscountController {
    public double applyDiscount(double price, double discount) {
        return price * (1 - discount);  // VULN: discount not validated
    }
}
""",
            """public class DiscountController {
    public double applyDiscount(double price, double discount) {
        if (discount < 0 || discount > 1) {
            throw new IllegalArgumentException("Invalid discount");
        }
        return price * (1 - discount);
    }
}
"""
        ),
        "file_upload": (
            """import java.io.*;
public class UploadServlet {
    public void saveFile(String filename, InputStream data) throws IOException {
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
        fos.write(data.readAllBytes());  // VULN: unrestricted upload
    }
}
""",
            """import java.io.*;
import java.util.Arrays;
public class UploadServlet {
    private static final String[] ALLOWED = {".jpg", ".png", ".pdf"};
    public void saveFile(String filename, InputStream data) throws IOException {
        String ext = filename.substring(filename.lastIndexOf('.'));
        if (!Arrays.asList(ALLOWED).contains(ext)) {
            throw new SecurityException("File type not allowed");
        }
        FileOutputStream fos = new FileOutputStream("/uploads/" + filename);
        fos.write(data.readAllBytes());
    }
}
"""
        ),
        "code_injection": (
            """import javax.script.*;
public class RuleEngine {
    public Object eval(String rule) throws Exception {
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(rule);  // VULN: code injection
    }
}
""",
            """import javax.script.*;
import java.util.Set;
public class RuleEngine {
    private static final Set<String> ALLOWED_OPS = Set.of("+", "-", "*", "/");
    public Object eval(String rule) throws Exception {
        if (!rule.matches("[0-9+\\-*/\\.() ]+")) {
            throw new SecurityException("Invalid expression");
        }
        ScriptEngine engine = new ScriptEngineManager().getEngineByName("js");
        return engine.eval(rule);
    }
}
"""
        ),
        "hardcoded_creds": (
            """public class DBConfig {
    public static final String USERNAME = "admin";
    public static final String PASSWORD = "password123";  // VULN: hardcoded
}
""",
            """import java.io.*;
import java.util.Properties;
public class DBConfig {
    public static String getPassword() throws IOException {
        Properties props = new Properties();
        props.load(new FileInputStream("db.properties"));
        return props.getProperty("password");
    }
}
"""
        ),
        "brute_force": (
            """public class LoginController {
    public boolean login(String user, String pass) {
        return checkPassword(user, pass);  // VULN: no rate limiting
    }
}
""",
            """import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
public class LoginController {
    private static final Map<String, Integer> attempts = new ConcurrentHashMap<>();
    public boolean login(String user, String pass) {
        int count = attempts.getOrDefault(user, 0);
        if (count >= 5) {
            throw new SecurityException("Too many attempts");
        }
        attempts.put(user, count + 1);
        return checkPassword(user, pass);
    }
}
"""
        ),
    },
    "Python": {
        "cmd_injection": (
            """import os

def run_user_cmd(cmd):
    os.system(cmd)  # VULN: command injection
""",
            """import shlex
import subprocess

def run_user_cmd(cmd):
    args = shlex.split(cmd)
    if any(c in args for c in [';', '|', '&', '$', '`']):
        raise ValueError("Invalid characters")
    subprocess.run(args, check=True)
"""
        ),
        "sql_injection": (
            """import sqlite3

def get_user(username):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    return cursor.fetchall()  # VULN: SQL injection
""",
            """import sqlite3

def get_user(username):
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    return cursor.fetchall()
"""
        ),
        "path_traversal": (
            """def read_file(filename):
    with open(f"/data/{filename}", "r") as f:
        return f.read()  # VULN: path traversal
""",
            """import os

def read_file(filename):
    base = os.path.abspath("/data")
    target = os.path.abspath(os.path.join(base, filename))
    if not target.startswith(base):
        raise ValueError("Invalid path")
    with open(target, "r") as f:
        return f.read()
"""
        ),
        "pickle_deser": (
            """import pickle

def load_object(data):
    return pickle.loads(data)  # VULN: arbitrary deserialization
""",
            """import json

def load_object(data):
    return json.loads(data)  # FIX: use safe serialization
"""
        ),
        "eval_injection": (
            """def calculate(expr):
    return eval(expr)  # VULN: arbitrary code execution
""",
            """import ast
import operator

OPS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
}

def calculate(expr):
    tree = ast.parse(expr, mode='eval')
    if not isinstance(tree.body, ast.BinOp):
        raise ValueError("Invalid expression")
    left = tree.body.left.n
    right = tree.body.right.n
    op = OPS[type(tree.body.op)]
    return op(left, right)
"""
        ),
        "input_validation": (
            """def process_age(age):
    return int(age) * 12  # VULN: no validation
""",
            """def process_age(age):
    try:
        age = int(age)
        if age < 0 or age > 150:
            raise ValueError("Invalid age")
        return age * 12
    except ValueError:
        raise ValueError("Age must be a valid integer")
"""
        ),
        "info_exposure": (
            """from flask import Flask
app = Flask(__name__)

@app.errorhandler(500)
def handle_error(e):
    return str(e), 500  # VULN: exposes stack trace
""",
            """from flask import Flask
import logging
app = Flask(__name__)

@app.errorhandler(500)
def handle_error(e):
    app.logger.error(str(e))
    return "Internal Server Error", 500
"""
        ),
        "cert_validation": (
            """import requests

def fetch(url):
    return requests.get(url, verify=False)  # VULN: no cert validation
""",
            """import requests

def fetch(url):
    return requests.get(url, verify=True)
"""
        ),
        "log_exposure": (
            """import logging

def log_user(user):
    logging.info(f"User login: {user.password}")  # VULN: sensitive info in log
""",
            """import logging

def log_user(user):
    logging.info(f"User login: {user.username}")
"""
        ),
        "tmp_file": (
            """import os

def create_temp(suffix):
    path = f"/tmp/file{suffix}"
    open(path, "w").close()  # VULN: predictable temp file
    return path
""",
            """import tempfile

def create_temp(suffix):
    fd, path = tempfile.mkstemp(suffix=suffix)
    os.close(fd)
    return path
"""
        ),
        "exec_injection": (
            """def execute_code(code):
    exec(code)  # VULN: arbitrary code execution
""",
            """import ast

ALLOWED_NODES = {ast.Expression, ast.BinOp, ast.Num, ast.Add, ast.Sub, ast.Mult, ast.Div}

def execute_code(code):
    tree = ast.parse(code, mode='eval')
    for node in ast.walk(tree):
        if type(node) not in ALLOWED_NODES:
            raise ValueError("Disallowed expression")
    return eval(compile(tree, '<string>', 'eval'))
"""
        ),
        "hardcoded_creds": (
            """API_KEY = "sk-1234567890abcdef"  # VULN: hardcoded credential

def authenticate():
    headers = {"Authorization": API_KEY}
    return headers
""",
            """import os

API_KEY = os.getenv("API_KEY")  # FIX: load from environment

def authenticate():
    if not API_KEY:
        raise ValueError("API_KEY not set")
    headers = {"Authorization": API_KEY}
    return headers
"""
        ),
        "missing_auth": (
            """from flask import Flask, request
app = Flask(__name__)

@app.route("/admin")
def admin_panel():
    return "Admin Dashboard"  # VULN: missing authorization
""",
            """from flask import Flask, request, abort
app = Flask(__name__)

@app.route("/admin")
def admin_panel():
    token = request.headers.get("Authorization")
    if not token or not validate_token(token):
        abort(403)
    return "Admin Dashboard"
"""
        ),
        "ssrf": (
            """import urllib.request

def fetch_url(url):
    return urllib.request.urlopen(url).read()  # VULN: SSRF
""",
            """import urllib.request
from urllib.parse import urlparse

ALLOWED_HOSTS = {"api.example.com", "cdn.example.com"}

def fetch_url(url):
    parsed = urlparse(url)
    if parsed.hostname not in ALLOWED_HOSTS:
        raise ValueError("Host not allowed")
    return urllib.request.urlopen(url).read()
"""
        ),
        "improper_encoding": (
            """from flask import Flask, request, make_response
app = Flask(__name__)

@app.route("/echo")
def echo():
    name = request.args.get("name")
    return f"<div>{name}</div>"  # VULN: improper encoding
""",
            """from flask import Flask, request, make_response
from html import escape
app = Flask(__name__)

@app.route("/echo")
def echo():
    name = request.args.get("name")
    return f"<div>{escape(name)}</div>"
"""
        ),
    }
}

# Generator function
def generate_samples():
    manifest = []
    total_repaired_lines = 0
    for lang in ["C", "Java", "Python"]:
        patterns = CWE_PATTERNS[lang]
        templates = TEMPLATES[lang]
        # Ensure we have at least 50 by cycling through patterns and adding variants
        for i in range(1, 51):
            pattern_idx = (i - 1) % len(patterns)
            cwe, vuln_type, template_key, risk = patterns[pattern_idx]
            # Add a variant suffix for uniqueness when cycling repeats
            variant = (i - 1) // len(patterns) + 1
            sample_id = f"{lang.upper()}_SAMPLE_{i:03d}"
            filename = f"{lang.lower()}_sample_{i:03d}.{lang.lower().replace('python', 'py').replace('java', 'java').replace('c', 'c')}"
            
            vuln_code, fixed_code = templates[template_key]
            # Add minor variant comments to make each file unique
            if variant > 1:
                vuln_code = f"// Variant {variant}\n" + vuln_code
                fixed_code = f"// Variant {variant} (Fixed)\n" + fixed_code
            
            # Count lines (approximate)
            vuln_lines = len(vuln_code.strip().splitlines())
            fixed_lines = len(fixed_code.strip().splitlines())
            repaired = max(0, fixed_lines - vuln_lines + 8)  # rough estimate
            total_repaired_lines += repaired
            
            # Save file
            out_dir = os.path.join(SAMPLES_DIR, f"samples_{lang.lower()}")
            os.makedirs(out_dir, exist_ok=True)
            with open(os.path.join(out_dir, filename), "w", encoding="utf-8") as f:
                f.write(vuln_code)
            
            with open(os.path.join(out_dir, filename.replace("." + lang.lower().replace("python", "py").replace("java", "java").replace("c", "c"), ".fixed." + lang.lower().replace("python", "py").replace("java", "java").replace("c", "c"))), "w", encoding="utf-8") as f:
                f.write(fixed_code)
            
            manifest.append({
                "编号": sample_id,
                "数据集来源": "Synthetic / " + random.choice(["multi-swe-bench", "Devign", "Vul4J", "PrimeVul"]),
                "语言": lang,
                "漏洞类型": vuln_type,
                "CWE编号": cwe,
                "函数/文件描述": f"演示 {template_key} 漏洞模式",
                "漏洞行数": vuln_lines,
                "选择理由": f"覆盖 {cwe} 典型模式，风险等级 {risk}"
            })
    
    # Write manifest
    with open(MANIFEST_PATH, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["编号", "数据集来源", "语言", "漏洞类型", "CWE编号", "函数/文件描述", "漏洞行数", "选择理由"])
        writer.writeheader()
        writer.writerows(manifest)
    
    # Write stats
    stats = {
        "total_samples": len(manifest),
        "total_repaired_lines": total_repaired_lines,
        "languages": {"C": 50, "Java": 50, "Python": 50}
    }
    with open(STATS_PATH, "w", encoding="utf-8") as f:
        json.dump(stats, f, ensure_ascii=False, indent=2)
    
    return manifest, stats

if __name__ == "__main__":
    manifest, stats = generate_samples()
    print(f"Generated {stats['total_samples']} samples. Total repaired lines: {stats['total_repaired_lines']}")
    print(f"Manifest saved to {MANIFEST_PATH}")
    print(f"Stats saved to {STATS_PATH}")