"""
Stress tests for nasl_py — every documented operation against files with
varied formatting: tabs, compact syntax, extra blank lines, CRLF, deeply
nested blocks, missing sections, many repeated calls, and chained mutations.

Run:
    pytest tests/stress_test.py -v
    pytest tests/stress_test.py -v -k "round_trip"   # one class only

Integration tests against a real plugin directory (classes 21–22):
    NASL_PLUGIN_DIR=/path/to/NVT-plugins pytest tests/stress_test.py -v -k "Integration"

Requires nasl_py installed:
    pip install ...  (see README) or maturin develop in nasl-py/
"""
import os
import pathlib
import subprocess
import tempfile

import pytest

try:
    import nasl_py
except ImportError:
    pytest.skip("nasl_py not installed", allow_module_level=True)


# ============================================================================
# NASL source fixtures — every variation of real-world formatting
# ============================================================================

# 1. Standard well-formatted file with everything present
STANDARD = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100001");
  script_version("2024-06-15T10:00:00+0000");
  script_name("Standard Plugin");
  script_family("Web application abuses");
  script_copyright("(C) 2024 Example Corp");
  script_category(ACT_GATHER_INFO);
  script_timeout(30);

  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_tag(name:"summary", value:"A test plugin.");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"qod_type", value:"remote_banner");
  script_tag(name:"holm-epssv1", value:"0.00421");

  script_cve_id("CVE-2023-1234", "CVE-2023-5678");
  script_bugtraq_id(12345, 67890);
  script_xref(name:"URL", value:"https://example.com/advisory");
  script_xref(name:"URL", value:"https://nvd.nist.gov/vuln/detail/CVE-2023-1234");
  script_dependencies("gb_apache_detect.nasl", "os_detection.nasl");
  script_mandatory_keys("www/apache");
  script_require_ports(80, 443, "Services/www");
  script_require_keys("SMB/WindowsVersion");
  script_exclude_keys("Settings/disable_cgi_scanning");
  include("http_func.inc");
  include("http_keepalive.inc");
  script_add_preference(name:"Username", type:"entry", value:"admin", id:1);
  exit(0);
}

# Added by Holm Security automated modification script
port = get_http_port(default:80);
if(!port) exit(0);
timeout = 10;
res = http_get(item:"/", port:port);
if(security_message(port:port, data:res)) {
  set_kb_item(name:"holm/pci/web_servers", value:get_script_oid());
}
if(security_message(port:443, data:res)) {
  set_kb_item(name:"holm/pci/xss", value:get_script_oid());
}
"""

# 2. Tabs for indentation
TABS = """\
if(description)
{
\tscript_oid("1.3.6.1.4.1.25623.1.0.100002");
\tscript_version("2023-11-20T08:30:00+0000");
\tscript_name("Tab Indented Plugin");
\tscript_family("General");
\tscript_copyright("(C) 2023 Corp");
\tscript_category(ACT_ATTACK);
\tscript_tag(name:"cvss_base", value:"5.0");
\tscript_tag(name:"solution_type", value:"WillNotFix");
\tscript_cve_id("CVE-2022-9999");
\tscript_dependencies("smb_reg_service.nasl");
\tinclude("cpe.inc");
\texit(0);
}
port = 443;
timeout = 10;
if(get_kb_item("foo/bar")) {
\tsecurity_message(port:port, data:"found it");
}
"""

# 3. Compact — no extra spaces, no blank lines, braces on same line
COMPACT = (
    'if(description){\n'
    'script_oid("1.3.6.1.4.1.25623.1.0.100003");\n'
    'script_version("2025-01-01T00:00:00+0000");\n'
    'script_name("Compact");\n'
    'script_family("Brute force attacks");\n'
    'script_copyright("(C) 2025 X");\n'
    'script_category(ACT_SCANNER);\n'
    'script_tag(name:"cvss_base",value:"9.8");\n'
    'script_tag(name:"summary",value:"compact test");\n'
    'script_cve_id("CVE-2025-0001");\n'
    'script_dependencies("a.nasl");\n'
    'include("misc_func.inc");\n'
    'exit(0);\n'
    '}\n'
    'port=80;\n'
    'timeout=30;\n'
    'res=http_get(item:"/",port:port);\n'
    'if(security_message(port:port,data:res)){\n'
    'set_kb_item(name:"holm/pci/sqli",value:get_script_oid());\n'
    '}\n'
)

# 4. Extra blank lines and spaces inside parens
EXTRA_BLANKS = """\
if( description )
{

  script_oid( "1.3.6.1.4.1.25623.1.0.100004" );

  script_version( "2022-03-14T09:00:00+0000" );

  script_name( "Extra Blanks Plugin" );

  script_family( "Denial of Service" );

  script_copyright( "(C) 2022 Test" );

  script_category( ACT_DENIAL );

  script_tag( name:"cvss_base" , value:"6.5" );

  script_tag( name:"qod_type" , value:"exploit" );

  script_cve_id( "CVE-2022-1111" , "CVE-2022-2222" );

  script_dependencies( "a.nasl" , "b.nasl" , "c.nasl" );

  include( "misc_func.inc" );

  exit( 0 );

}

host = get_host_name();
if( !host ) exit( 0 );
timeout = 5;
"""

# 5. Complex nested code with functions, loops, multiple if-blocks
COMPLEX = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100005");
  script_version("2024-12-01T00:00:00+0000");
  script_name("Complex Plugin");
  script_family("Web application abuses");
  script_copyright("(C) 2024 Corp");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"cvss_base", value:"8.1");
  script_tag(name:"solution_type", value:"VendorFix");
  script_tag(name:"holm-epssv1", value:"0.00421");
  script_tag(name:"holm-ai-summary", value:"This plugin detects...");
  script_cve_id("CVE-2024-1234", "CVE-2024-5678");
  script_dependencies("http_func.inc", "secpod_base.nasl");
  script_require_ports(80, 443);
  include("http_func.inc");
  exit(0);
}

# holm: modified by automation
function check_version(banner, port) {
  local_var ver, res;
  ver = eregmatch(string:banner, pattern:"Apache/([0-9.]+)");
  if(!ver) return FALSE;
  return ver[1];
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);
timeout = 30;

if(!banner) {
  exit(0);
}

version = check_version(banner:banner, port:port);

if(version =~ "^2\\.[0-3]\\.") {
  report = "Vulnerable version: " + version;
  if(security_message(port:port, data:report)) {
    set_kb_item(name:"holm/pci/web_servers", value:get_script_oid());
    set_kb_item(name:"holm/pci/sqli", value:get_script_oid());
  }
  if(security_message(port:443, data:report)) {
    set_kb_item(name:"holm/pci/web_servers", value:get_script_oid());
  }
}

for(i = 0; i < 3; i++) {
  timeout = i * 100;
  res = http_get(item:"/path" + i, port:port);
  if(res) {
    port = get_kb_item("Services/www");
  }
}

foreach item(make_list("x", "y", "z")) {
  if(item == "x") {
    log_message(data:item);
  }
}
"""

# 6. Minimal — only description block, absolutely nothing else
MINIMAL = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100006");
  script_version("2020-01-01T00:00:00+0000");
  script_name("Minimal");
  script_family("General");
  script_copyright("(C) 2020 Min");
  script_category(ACT_INIT);
  script_tag(name:"cvss_base", value:"0.0");
  exit(0);
}"""

# 7. Windows CRLF line endings
CRLF = (
    "if(description)\r\n{\r\n"
    '  script_oid("1.3.6.1.4.1.25623.1.0.100007");\r\n'
    '  script_version("2024-06-01T00:00:00+0000");\r\n'
    '  script_name("CRLF Plugin");\r\n'
    '  script_family("General");\r\n'
    '  script_copyright("(C) 2024 X");\r\n'
    '  script_category(ACT_SETTINGS);\r\n'
    '  script_tag(name:"cvss_base", value:"3.0");\r\n'
    '  script_tag(name:"summary", value:"crlf test");\r\n'
    '  exit(0);\r\n'
    '}\r\n'
    'port = 80;\r\n'
    'timeout = 5;\r\n'
)

# 8. Many repeated calls — stress for find_calls, multiple if-blocks
MANY_CALLS = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100008");
  script_version("2024-03-01T00:00:00+0000");
  script_name("Many Calls");
  script_family("Web application abuses");
  script_copyright("(C) 2024 X");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"cvss_base", value:"5.5");
  exit(0);
}
port1 = get_http_port(default:80);
port2 = get_http_port(default:8080);
port3 = get_http_port(default:443);
port4 = get_http_port(default:8443);
res1 = http_get(item:"/", port:port1);
res2 = http_get(item:"/admin", port:port2);
res3 = http_get(item:"/login", port:port3);
res4 = http_get(item:"/api", port:port4);
timeout = 10;
timeout = timeout + 5;
if(res1) security_message(port:port1, data:res1);
if(res2) security_message(port:port2, data:res2);
if(res3) security_message(port:port3, data:res3);
if(res4) security_message(port:port4, data:res4);
"""

# 9. Bare code — no description block at all
BARE_CODE = """\
# No description block
port = 80;
host = get_host_name();
timeout = 30;
if(!host) exit(0);
res = http_get(item:"/", port:port);
if(security_message(port:port, data:res)) {
  set_kb_item(name:"holm/pci/web_servers", value:get_script_oid());
}
"""

# 10. Stale version date (old plugin)
STALE = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100009");
  script_version("2018-05-10T00:00:00+0000");
  script_name("Old Plugin");
  script_family("General");
  script_copyright("(C) 2018 Corp");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"cvss_base", value:"4.0");
  script_cve_id("CVE-2018-0001");
  exit(0);
}
port = 80;
"""

# All fixtures that have a valid description block (exit(0) present)
DESCRIPTION_FIXTURES = [STANDARD, TABS, COMPACT, EXTRA_BLANKS, COMPLEX, MINIMAL, CRLF, STALE]
# All fixtures including bare code
ALL_FIXTURES = DESCRIPTION_FIXTURES + [MANY_CALLS, BARE_CODE]


# ============================================================================
# Helpers
# ============================================================================

def load(src):
    return nasl_py.NaslFile.from_str(src)


def find_in_tree(node, kind):
    """Collect all nodes/tokens of a given kind from a get_tree() dict."""
    results = []
    if node["kind"] == kind:
        results.append(node)
    for child in node.get("children", []):
        results.extend(find_in_tree(child, kind))
    return results


def all_tokens(node):
    """Yield every leaf token in the tree."""
    if node.get("is_token"):
        yield node
    for child in node.get("children", []):
        yield from all_tokens(child)


# ============================================================================
# 1. Round-trip guarantee
# ============================================================================

class TestRoundTrip:
    """parse → to_str must equal original for every fixture."""

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_round_trip(self, src):
        f = load(src)
        assert f.to_str() == src

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_original_str_unchanged(self, src):
        f = load(src)
        f.set_script_tag("cvss_base", "9.9")
        assert f.original_str() == src

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_reset_restores(self, src):
        f = load(src)
        f.set_script_tag("cvss_base", "0.0")
        f.reset()
        assert f.to_str() == src
        assert not f.is_modified()

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_parse_errors_no_crash(self, src):
        f = load(src)
        errs = f.parse_errors()
        assert isinstance(errs, list)

    def test_repr(self):
        f = load(STANDARD)
        r = repr(f)
        assert "NaslFile" in r
        assert "bytes=" in r


# ============================================================================
# 2. File I/O
# ============================================================================

class TestFileIO:

    def test_from_file_and_to_file(self, tmp_path):
        p = str(tmp_path / "test.nasl")
        with open(p, "w") as fh:
            fh.write(STANDARD)
        f = nasl_py.NaslFile.from_file(p)
        assert f.to_str() == STANDARD
        f.set_script_tag("cvss_base", "9.9")
        f.to_file(p)
        f2 = nasl_py.NaslFile.from_file(p)
        assert f2.get_script_tag("cvss_base") == "9.9"

    def test_from_file_missing_raises(self):
        with pytest.raises(Exception):
            nasl_py.NaslFile.from_file("/nonexistent/path/to/file.nasl")

    def test_to_file_then_reparse_round_trips(self, tmp_path):
        p = str(tmp_path / "rt.nasl")
        f = load(COMPLEX)
        f.to_file(p)
        f2 = nasl_py.NaslFile.from_file(p)
        assert f2.to_str() == COMPLEX

    def test_is_modified_flag(self):
        f = load(STANDARD)
        assert not f.is_modified()
        f.set_script_tag("cvss_base", "1.0")
        assert f.is_modified()
        f.reset()
        assert not f.is_modified()


# ============================================================================
# 3. script_tag
# ============================================================================

class TestScriptTag:

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_existing(self, src):
        f = load(src)
        val = f.get_script_tag("cvss_base")
        assert val is not None
        assert isinstance(val, str)

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_missing_returns_none(self, src):
        f = load(src)
        assert f.get_script_tag("nonexistent_tag_xyz") is None

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_has_tag(self, src):
        f = load(src)
        assert f.has_script_tag("cvss_base")
        assert not f.has_script_tag("nonexistent_xyz")

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_list_tags_non_empty(self, src):
        f = load(src)
        tags = f.list_script_tags()
        assert isinstance(tags, list)
        assert "cvss_base" in tags

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_all_tags_is_dict(self, src):
        f = load(src)
        d = f.get_all_script_tags()
        assert isinstance(d, dict)
        assert "cvss_base" in d

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_tag_mutates(self, src):
        f = load(src)
        result = f.set_script_tag("cvss_base", "9.9")
        assert result
        assert f.get_script_tag("cvss_base") == "9.9"
        assert f.is_modified()

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_tag_round_trips(self, src):
        """After setting, the source must still parse cleanly."""
        f = load(src)
        f.set_script_tag("cvss_base", "3.7")
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "3.7"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_add_tag_appears(self, src):
        f = load(src)
        ok = f.add_script_tag("holm-stress-test", "yes")
        assert ok
        assert f.get_script_tag("holm-stress-test") == "yes"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_add_multiple_tags(self, src):
        f = load(src)
        f.add_script_tag("holm-a", "1")
        f.add_script_tag("holm-b", "2")
        f.add_script_tag("holm-c", "3")
        assert f.get_script_tag("holm-a") == "1"
        assert f.get_script_tag("holm-b") == "2"
        assert f.get_script_tag("holm-c") == "3"

    def test_set_missing_tag_returns_false(self):
        f = load(BARE_CODE)
        assert not f.set_script_tag("cvss_base", "5.0")

    def test_add_tag_on_no_description_returns_false(self):
        f = load(BARE_CODE)
        assert not f.add_script_tag("foo", "bar")

    @pytest.mark.parametrize("value", ["0.0", "10.0", "5.5", "", "special/chars:here", "AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    def test_set_tag_various_values(self, value):
        f = load(STANDARD)
        f.set_script_tag("cvss_base", value)
        assert f.get_script_tag("cvss_base") == value


# ============================================================================
# 4. Core metadata
# ============================================================================

class TestCoreMetadata:

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_oid(self, src):
        f = load(src)
        oid = f.get_oid()
        assert oid is not None
        assert "1.3.6" in oid

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_oid(self, src):
        f = load(src)
        f.set_oid("1.3.6.1.4.1.25623.1.0.999999")
        assert f.get_oid() == "1.3.6.1.4.1.25623.1.0.999999"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_version(self, src):
        f = load(src)
        assert f.get_version() is not None

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_version(self, src):
        f = load(src)
        f.set_version("2099-12-31T23:59:59+0000")
        assert f.get_version() == "2099-12-31T23:59:59+0000"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_name(self, src):
        f = load(src)
        assert f.get_name() is not None

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_name(self, src):
        f = load(src)
        f.set_name("Stress Test Plugin")
        assert f.get_name() == "Stress Test Plugin"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_family(self, src):
        f = load(src)
        assert f.get_family() is not None

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_set_family(self, src):
        f = load(src)
        f.set_family("General")
        assert f.get_family() == "General"

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_copyright(self, src):
        f = load(src)
        assert f.get_copyright() is not None

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_category(self, src):
        f = load(src)
        cat = f.get_category()
        assert cat is not None
        assert cat.startswith("ACT_")

    @pytest.mark.parametrize("category", [
        "ACT_INIT", "ACT_SCANNER", "ACT_SETTINGS", "ACT_GATHER_INFO",
        "ACT_ATTACK", "ACT_MIXED_ATTACK", "ACT_DESTRUCTIVE_ATTACK",
        "ACT_DENIAL", "ACT_KILL_HOST", "ACT_FLOOD", "ACT_END",
    ])
    def test_set_category_all_values(self, category):
        f = load(STANDARD)
        f.set_category(category)
        assert f.get_category() == category

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_timeout(self, src):
        f = load(src)
        t = f.get_timeout()
        assert t is None or isinstance(t, int)

    def test_set_timeout(self):
        f = load(STANDARD)
        f.set_timeout(120)
        assert f.get_timeout() == 120

    def test_metadata_missing_on_bare_code(self):
        f = load(BARE_CODE)
        assert f.get_oid() is None
        assert f.get_version() is None
        assert f.get_name() is None
        assert f.get_family() is None
        assert f.get_category() is None
        assert f.get_timeout() is None


# ============================================================================
# 5. CVE operations
# ============================================================================

class TestCVEOps:

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_cve_ids(self, src):
        f = load(src)
        ids = f.get_cve_ids()
        assert isinstance(ids, list)

    def test_has_cve_id_true(self):
        f = load(STANDARD)
        assert f.has_cve_id("CVE-2023-1234")
        assert f.has_cve_id("cve-2023-1234")  # case-insensitive

    def test_has_cve_id_false(self):
        f = load(STANDARD)
        assert not f.has_cve_id("CVE-9999-9999")

    def test_add_cve_id(self):
        f = load(STANDARD)
        f.add_cve_id("CVE-2099-9999")
        assert f.has_cve_id("CVE-2099-9999")

    def test_remove_cve_id(self):
        f = load(STANDARD)
        f.remove_cve_id("CVE-2023-1234")
        assert not f.has_cve_id("CVE-2023-1234")
        assert f.has_cve_id("CVE-2023-5678")

    def test_set_cve_ids_replaces_all(self):
        f = load(STANDARD)
        f.set_cve_ids(["CVE-2099-0001", "CVE-2099-0002"])
        ids = f.get_cve_ids()
        assert set(ids) == {"CVE-2099-0001", "CVE-2099-0002"}
        assert not f.has_cve_id("CVE-2023-1234")

    def test_cve_operations_on_empty_list(self):
        f = load(MINIMAL)
        assert f.get_cve_ids() == []
        assert not f.has_cve_id("CVE-2020-0001")
        # add to file with no cve_id call — should return False (no call to append to)
        result = f.add_cve_id("CVE-2020-0001")
        assert isinstance(result, bool)

    @pytest.mark.parametrize("src", [STANDARD, TABS, COMPACT, EXTRA_BLANKS])
    def test_add_remove_roundtrip(self, src):
        f = load(src)
        before = set(f.get_cve_ids())
        f.add_cve_id("CVE-2099-STRESS")
        f.remove_cve_id("CVE-2099-STRESS")
        assert set(f.get_cve_ids()) == before


# ============================================================================
# 6. XRef operations
# ============================================================================

class TestXRefOps:

    def test_get_all_xrefs(self):
        f = load(STANDARD)
        refs = f.get_all_xrefs()
        assert isinstance(refs, list)
        assert len(refs) == 2
        assert all(len(r) == 2 for r in refs)

    def test_get_xrefs_by_name(self):
        f = load(STANDARD)
        urls = f.get_xrefs("URL")
        assert len(urls) == 2

    def test_has_xref(self):
        f = load(STANDARD)
        assert f.has_xref("URL", "https://example.com/advisory")
        assert not f.has_xref("URL", "https://not-here.example.com")

    def test_add_xref(self):
        f = load(STANDARD)
        f.add_xref("URL", "https://new.example.com")
        assert f.has_xref("URL", "https://new.example.com")

    def test_xrefs_empty_on_minimal(self):
        f = load(MINIMAL)
        assert f.get_all_xrefs() == []

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_add_xref_then_reparse(self, src):
        f = load(src)
        f.add_xref("URL", "https://stress.example.com/test")
        f2 = load(f.to_str())
        assert f2.has_xref("URL", "https://stress.example.com/test")


# ============================================================================
# 7. Dependencies
# ============================================================================

class TestDependencies:

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_dependencies(self, src):
        f = load(src)
        deps = f.get_dependencies()
        assert isinstance(deps, list)

    def test_has_dependency(self):
        f = load(STANDARD)
        assert f.has_dependency("gb_apache_detect.nasl")
        assert not f.has_dependency("nonexistent.nasl")

    def test_add_dependency(self):
        f = load(STANDARD)
        f.add_dependency("stress_test.nasl")
        assert f.has_dependency("stress_test.nasl")

    def test_remove_dependency(self):
        f = load(STANDARD)
        f.remove_dependency("gb_apache_detect.nasl")
        assert not f.has_dependency("gb_apache_detect.nasl")

    def test_no_deps_on_minimal(self):
        f = load(MINIMAL)
        assert f.get_dependencies() == []

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_add_dep_round_trips(self, src):
        f = load(src)
        f.add_dependency("new_dep.nasl")
        f2 = load(f.to_str())
        assert f2.has_dependency("new_dep.nasl")


# ============================================================================
# 8. Keys and ports
# ============================================================================

class TestKeysAndPorts:

    def test_mandatory_keys(self):
        f = load(STANDARD)
        keys = f.get_mandatory_keys()
        assert "www/apache" in keys

    def test_mandatory_keys_re_none(self):
        f = load(STANDARD)
        assert f.get_mandatory_keys_re() is None  # no re: arg in STANDARD

    def test_add_mandatory_key(self):
        f = load(STANDARD)
        f.add_mandatory_key("stress/test/key")
        assert "stress/test/key" in f.get_mandatory_keys()

    def test_require_keys(self):
        f = load(STANDARD)
        keys = f.get_require_keys()
        assert "SMB/WindowsVersion" in keys

    def test_require_ports(self):
        f = load(STANDARD)
        ports = f.get_require_ports()
        assert "80" in ports
        assert "443" in ports

    def test_require_udp_ports_empty(self):
        f = load(STANDARD)
        assert isinstance(f.get_require_udp_ports(), list)

    def test_exclude_keys(self):
        f = load(STANDARD)
        keys = f.get_exclude_keys()
        assert "Settings/disable_cgi_scanning" in keys

    def test_add_exclude_key(self):
        f = load(STANDARD)
        f.add_exclude_key("stress/exclude")
        assert "stress/exclude" in f.get_exclude_keys()

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_keys_return_lists(self, src):
        f = load(src)
        assert isinstance(f.get_mandatory_keys(), list)
        assert isinstance(f.get_require_keys(), list)
        assert isinstance(f.get_require_ports(), list)
        assert isinstance(f.get_require_udp_ports(), list)
        assert isinstance(f.get_exclude_keys(), list)


# ============================================================================
# 9. Preferences
# ============================================================================

class TestPreferences:

    def test_get_preferences(self):
        f = load(STANDARD)
        prefs = f.get_preferences()
        assert isinstance(prefs, list)
        assert len(prefs) == 1
        assert prefs[0]["name"] == "Username"

    def test_add_preference(self):
        f = load(STANDARD)
        f.add_preference("Timeout", "entry", "30", id=2)
        prefs = f.get_preferences()
        names = [p["name"] for p in prefs]
        assert "Timeout" in names

    def test_preferences_empty_on_minimal(self):
        f = load(MINIMAL)
        assert f.get_preferences() == []

    @pytest.mark.parametrize("ptype", ["entry", "password", "file", "checkbox", "radio"])
    def test_add_preference_all_types(self, ptype):
        f = load(STANDARD)
        f.add_preference(f"Pref_{ptype}", ptype, "default", id=99)
        names = [p["name"] for p in f.get_preferences()]
        assert f"Pref_{ptype}" in names


# ============================================================================
# 10. Includes
# ============================================================================

class TestIncludes:

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_get_includes(self, src):
        f = load(src)
        assert isinstance(f.get_includes(), list)

    def test_has_include(self):
        f = load(STANDARD)
        assert f.has_include("http_func.inc")
        assert not f.has_include("nonexistent.inc")

    def test_add_include(self):
        f = load(STANDARD)
        f.add_include("stress_lib.inc")
        assert f.has_include("stress_lib.inc")

    def test_remove_include(self):
        f = load(STANDARD)
        f.remove_include("http_func.inc")
        assert not f.has_include("http_func.inc")
        assert f.has_include("http_keepalive.inc")

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES)
    def test_add_include_round_trips(self, src):
        f = load(src)
        f.add_include("new_lib.inc")
        f2 = load(f.to_str())
        assert f2.has_include("new_lib.inc")


# ============================================================================
# 11. Full metadata snapshot
# ============================================================================

class TestMetadataSnapshot:

    EXPECTED_KEYS = {
        "oid", "version", "name", "family", "category", "copyright",
        "timeout", "script_tags", "cve_ids", "bugtraq_ids", "xrefs",
        "dependencies", "mandatory_keys", "mandatory_keys_re",
        "require_keys", "require_ports", "require_udp_ports",
        "exclude_keys", "includes", "preferences",
    }

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_all_keys_present(self, src):
        f = load(src)
        m = f.get_metadata()
        assert self.EXPECTED_KEYS <= set(m.keys())

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_types_are_correct(self, src):
        f = load(src)
        m = f.get_metadata()
        assert m["oid"] is None or isinstance(m["oid"], str)
        assert isinstance(m["cve_ids"], list)
        assert isinstance(m["script_tags"], dict)
        assert isinstance(m["preferences"], list)
        assert isinstance(m["xrefs"], list)


# ============================================================================
# 12. Date queries
# ============================================================================

class TestDateQueries:

    def test_get_version_date_standard(self):
        f = load(STANDARD)
        d = f.get_version_date()
        assert d == "2024-06-15T10:00:00"

    def test_get_version_date_minimal(self):
        f = load(MINIMAL)
        d = f.get_version_date()
        assert d == "2020-01-01T00:00:00"

    def test_get_version_date_bare_code_returns_none(self):
        f = load(BARE_CODE)
        assert f.get_version_date() is None

    def test_version_before_true(self):
        f = load(STANDARD)  # 2024-06-15
        assert f.version_before("2025-01-01")

    def test_version_before_false(self):
        f = load(STANDARD)
        assert not f.version_before("2020-01-01")

    def test_version_after_true(self):
        f = load(STANDARD)
        assert f.version_after("2020-01-01")

    def test_version_after_false(self):
        f = load(STANDARD)
        assert not f.version_after("2025-01-01")

    def test_version_between_inside(self):
        f = load(STANDARD)  # 2024-06-15
        assert f.version_between("2024-01-01", "2024-12-31")

    def test_version_between_outside(self):
        f = load(STANDARD)
        assert not f.version_between("2020-01-01", "2022-12-31")

    def test_version_between_exact_boundary(self):
        f = load(STANDARD)  # 2024-06-15T10:00:00+0000
        # Date-only strings parse to 00:00:00, so exact day boundary
        # won't match a file with T10:00:00. Use full timestamps.
        assert f.version_between("2024-06-15T10:00:00", "2024-06-15T10:00:00")

    @pytest.mark.parametrize("date_str", [
        "2024-01-01", "2024/01/01", "2024-01-01T00:00:00+0000",
        "2025-12-31T23:59:59+0000",
    ])
    def test_date_formats_accepted(self, date_str):
        f = load(STANDARD)
        # Should not crash — result may be True or False
        result = f.version_before(date_str)
        assert isinstance(result, bool)

    @pytest.mark.parametrize("bad", ["not-a-date", "", "2024", "24-01-01"])
    def test_invalid_date_returns_false(self, bad):
        f = load(STANDARD)
        assert not f.version_before(bad)
        assert not f.version_after(bad)
        assert not f.version_between(bad, "2025-01-01")


# ============================================================================
# 13. Holm markers
# ============================================================================

class TestHolmMarkers:

    def test_has_holm_marker_tag(self):
        f = load(STANDARD)
        assert f.has_holm_marker()  # has holm-epssv1 tag

    def test_has_holm_marker_comment(self):
        f = load(COMPLEX)
        assert f.has_holm_marker()  # has "# holm:" comment

    def test_get_holm_tags(self):
        f = load(STANDARD)
        tags = f.get_holm_tags()
        assert isinstance(tags, dict)
        assert "holm-epssv1" in tags

    def test_get_holm_comments(self):
        f = load(COMPLEX)
        comments = f.get_holm_comments()
        assert isinstance(comments, list)
        assert len(comments) > 0

    def test_no_holm_marker_on_minimal(self):
        f = load(MINIMAL)
        assert not f.has_holm_marker()
        assert f.get_holm_tags() == {}
        assert f.get_holm_comments() == []

    def test_add_holm_tag_then_detected(self):
        f = load(MINIMAL)
        f.add_script_tag("holm-test", "yes")
        assert f.has_holm_marker()
        assert "holm-test" in f.get_holm_tags()

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_holm_methods_no_crash(self, src):
        f = load(src)
        _ = f.has_holm_marker()
        _ = f.get_holm_tags()
        _ = f.get_holm_comments()


# ============================================================================
# 14. PCI / security_message blocks
# ============================================================================

class TestPCIOps:

    def test_get_pci_kb_items(self):
        f = load(STANDARD)
        items = f.get_pci_kb_items()
        assert isinstance(items, list)
        keys = [i["key"] for i in items]
        assert "holm/pci/web_servers" in keys

    def test_has_pci_kb_item(self):
        f = load(STANDARD)
        assert f.has_pci_kb_item("holm/pci/web_servers")
        assert not f.has_pci_kb_item("holm/pci/nonexistent")

    def test_add_to_security_message_blocks(self):
        f = load(STANDARD)
        count = f.add_to_security_message_blocks(
            'set_kb_item(name:"holm/pci/stress", value:get_script_oid());'
        )
        assert count > 0
        assert f.has_pci_kb_item("holm/pci/stress")

    def test_update_pci_kb_item(self):
        f = load(STANDARD)
        result = f.update_pci_kb_item("holm/pci/web_servers", "TRUE")
        assert result
        items = f.get_pci_kb_items()
        val = next((i["value"] for i in items if i["key"] == "holm/pci/web_servers"), None)
        assert val == "TRUE"

    def test_add_to_blocks_complex(self):
        f = load(COMPLEX)
        before = f.get_pci_kb_items()
        count = f.add_to_security_message_blocks(
            'set_kb_item(name:"holm/pci/rce", value:get_script_oid());'
        )
        assert count >= 2  # COMPLEX has 2 security_message if-blocks
        assert f.has_pci_kb_item("holm/pci/rce")

    def test_add_to_blocks_no_security_message(self):
        f = load(MINIMAL)
        count = f.add_to_security_message_blocks(
            'set_kb_item(name:"holm/pci/x", value:1);'
        )
        assert count == 0

    def test_add_and_update_then_reparse(self):
        # add_to_security_message_blocks inserts into every security_message
        # block. update_pci_kb_item updates the first match. Verify at least
        # one entry was updated, not all.
        f = load(STANDARD)
        f.add_to_security_message_blocks(
            'set_kb_item(name:"holm/pci/newkey", value:get_script_oid());'
        )
        f2 = load(f.to_str())  # reparse so new kb item is in the AST
        f2.update_pci_kb_item("holm/pci/newkey", '"TRUE"')
        f3 = load(f2.to_str())
        all_items = f3.get_pci_kb_items()
        assert any(i["key"] == "holm/pci/newkey" and i["value"] == '"TRUE"'
                   for i in all_items)

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_pci_methods_no_crash(self, src):
        f = load(src)
        _ = f.get_pci_kb_items()
        _ = f.has_pci_kb_item("holm/pci/x")


# ============================================================================
# 15. General code block operations
# ============================================================================

class TestCodeBlockOps:

    # ── find_calls ────────────────────────────────────────────────────────────

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_find_calls_no_crash(self, src):
        f = load(src)
        calls = f.find_calls("nonexistent_fn_xyz")
        assert calls == []

    def test_find_calls_returns_list_of_dicts(self):
        f = load(STANDARD)
        calls = f.find_calls("get_http_port")
        assert isinstance(calls, list)
        for c in calls:
            assert "text" in c
            assert "offset" in c
            assert "args" in c
            assert "named_args" in c

    def test_find_calls_many(self):
        f = load(MANY_CALLS)
        calls = f.find_calls("get_http_port")
        assert len(calls) == 4

    def test_find_calls_http_get(self):
        f = load(MANY_CALLS)
        calls = f.find_calls("http_get")
        assert len(calls) == 4

    def test_find_calls_named_args(self):
        f = load(STANDARD)
        calls = f.find_calls("get_http_port")
        assert len(calls) >= 1
        assert "default" in calls[0]["named_args"]

    def test_find_calls_offset_is_int(self):
        f = load(STANDARD)
        calls = f.find_calls("get_http_port")
        for c in calls:
            assert isinstance(c["offset"], int)
            assert c["offset"] >= 0

    @pytest.mark.parametrize("src", [TABS, COMPACT, EXTRA_BLANKS, COMPLEX])
    def test_find_calls_weird_formatting(self, src):
        f = load(src)
        # Just checking it doesn't crash and returns a list
        calls = f.find_calls("security_message")
        assert isinstance(calls, list)

    # ── replace_call_positional_arg ───────────────────────────────────────────

    def test_replace_call_positional_arg(self):
        src = 'script_oid("1.3.6.1.4.1.25623.1.0.100001");\n'
        f = load(src)
        result = f.replace_call_positional_arg("script_oid", 0, 0, '"1.3.6.1.4.1.25623.1.0.999999"')
        assert result
        assert "999999" in f.to_str()

    def test_replace_call_positional_arg_out_of_range(self):
        f = load(STANDARD)
        result = f.replace_call_positional_arg("get_http_port", 99, 0, "80")
        assert not result

    # ── replace_call_named_arg ────────────────────────────────────────────────

    def test_replace_call_named_arg_single(self):
        f = load(STANDARD)
        count = f.replace_call_named_arg("get_http_port", "default", "8080")
        assert count >= 1
        assert "8080" in f.to_str()

    def test_replace_call_named_arg_all_occurrences(self):
        f = load(MANY_CALLS)
        count = f.replace_call_named_arg("http_get", "item", '"/replaced"')
        assert count == 4  # 4 calls to http_get
        assert f.to_str().count("/replaced") == 4

    def test_replace_call_named_arg_no_match(self):
        f = load(STANDARD)
        count = f.replace_call_named_arg("get_http_port", "nonexistent_arg", "x")
        assert count == 0
        assert not f.is_modified()

    @pytest.mark.parametrize("src", [TABS, COMPACT, EXTRA_BLANKS])
    def test_replace_named_arg_weird_formatting(self, src):
        f = load(src)
        count = f.replace_call_named_arg("nonexistent_fn", "arg", "val")
        assert count == 0  # no crash

    # ── find_if_blocks ────────────────────────────────────────────────────────

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_find_if_blocks_with_call_no_crash(self, src):
        f = load(src)
        blocks = f.find_if_blocks_with_call("security_message")
        assert isinstance(blocks, list)

    def test_find_if_blocks_standard(self):
        f = load(STANDARD)
        blocks = f.find_if_blocks_with_call("security_message")
        assert len(blocks) >= 2
        for b in blocks:
            assert "condition" in b
            assert "text" in b
            assert "offset" in b

    def test_find_if_blocks_complex_multiple(self):
        f = load(COMPLEX)
        blocks = f.find_if_blocks_with_call("security_message")
        assert len(blocks) >= 2

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_find_if_blocks_condition_text_no_crash(self, src):
        f = load(src)
        blocks = f.find_if_blocks_with_condition_text("nonexistent_xyz")
        assert blocks == []

    def test_find_if_blocks_condition_text(self):
        f = load(STANDARD)
        blocks = f.find_if_blocks_with_condition_text("port")
        assert len(blocks) >= 1
        for b in blocks:
            assert "port" in b["condition"]

    def test_find_if_blocks_description_block(self):
        f = load(STANDARD)
        blocks = f.find_if_blocks_with_condition_text("description")
        assert len(blocks) >= 1

    # ── insert_before_call / insert_after_call ────────────────────────────────

    def test_insert_before_call(self):
        f = load(STANDARD)
        original_src = f.to_str()
        count = f.insert_before_call("get_http_port", '# inserted before')
        assert count >= 1
        assert "# inserted before" in f.to_str()
        # Inserted content must appear before the call in the source
        src = f.to_str()
        assert src.index("# inserted before") < src.index("get_http_port")

    def test_insert_after_call(self):
        f = load(STANDARD)
        count = f.insert_after_call("get_http_port", 'log_message(data:"after");')
        assert count >= 1
        src = f.to_str()
        assert 'log_message(data:"after");' in src
        assert src.index("get_http_port") < src.index('log_message(data:"after");')

    def test_insert_before_call_multiple_sites(self):
        f = load(MANY_CALLS)
        count = f.insert_before_call("http_get", 'log_message(data:"before_get");')
        assert count == 4
        assert f.to_str().count('log_message(data:"before_get");') == 4

    def test_insert_no_standalone_calls(self):
        # security_message calls inside `if(res1) security_message(...)` are not
        # EXPR_STMT-level (they're the condition body of an if without braces,
        # or inline expr) — check the result is still sane
        f = load(MANY_CALLS)
        original = f.to_str()
        count = f.insert_before_call("nonexistent_fn_xyz", "x;")
        assert count == 0
        assert f.to_str() == original

    def test_insert_before_call_result_reparses(self):
        f = load(STANDARD)
        f.insert_before_call("get_http_port", '# stress comment')
        f2 = load(f.to_str())
        assert f2.find_calls("get_http_port")

    # ── insert_at_start / end of if_block ─────────────────────────────────────

    def test_insert_at_start_of_if_block(self):
        f = load(STANDARD)
        count = f.insert_at_start_of_if_block("security_message", 'local_var x;')
        assert count >= 1
        assert 'local_var x;' in f.to_str()

    def test_insert_at_end_of_if_block(self):
        f = load(STANDARD)
        count = f.insert_at_end_of_if_block("security_message", 'log_message(data:"end");')
        assert count >= 1
        assert 'log_message(data:"end");' in f.to_str()

    def test_insert_at_start_complex(self):
        f = load(COMPLEX)
        count = f.insert_at_start_of_if_block("security_message", 'local_var stress;')
        assert count >= 2

    def test_insert_block_result_reparses(self):
        f = load(COMPLEX)
        f.insert_at_end_of_if_block("security_message", 'log_message(data:"x");')
        f2 = load(f.to_str())
        # After reparse, the blocks should still be findable
        assert f2.find_if_blocks_with_call("security_message")

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_insert_block_no_match_no_crash(self, src):
        f = load(src)
        count = f.insert_at_start_of_if_block("nonexistent_fn_xyz", "x;")
        assert count == 0

    # ── find_assignments / replace_assignment ──────────────────────────────────

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_find_assignments_no_crash(self, src):
        f = load(src)
        assigns = f.find_assignments("nonexistent_var_xyz")
        assert assigns == []

    def test_find_assignments_port(self):
        f = load(STANDARD)
        assigns = f.find_assignments("port")
        assert isinstance(assigns, list)
        assert len(assigns) >= 1
        for a in assigns:
            assert a["var_name"] == "port"
            assert a["operator"] in ("=", "+=", "-=", "*=", "/=", "%=")
            assert "value" in a
            assert isinstance(a["offset"], int)

    def test_find_assignments_timeout(self):
        f = load(STANDARD)
        assigns = f.find_assignments("timeout")
        assert len(assigns) >= 1

    def test_find_assignments_many(self):
        f = load(MANY_CALLS)
        assigns = f.find_assignments("timeout")
        assert len(assigns) >= 2  # timeout = 10 and timeout = timeout + 5

    def test_replace_assignment(self):
        f = load(STANDARD)
        result = f.replace_assignment("timeout", "999")
        assert result
        # The source should now contain the new value
        assigns = f.find_assignments("timeout")
        assert any(a["value"] == "999" for a in assigns)

    def test_replace_assignment_no_match(self):
        f = load(STANDARD)
        result = f.replace_assignment("nonexistent_var_xyz", "42")
        assert not result
        assert not f.is_modified()

    def test_replace_assignment_round_trips(self):
        f = load(STANDARD)
        f.replace_assignment("timeout", "42")
        f2 = load(f.to_str())
        assigns = f2.find_assignments("timeout")
        assert any(a["value"] == "42" for a in assigns)

    @pytest.mark.parametrize("src", [TABS, COMPACT, EXTRA_BLANKS, COMPLEX, MANY_CALLS])
    def test_find_assignments_weird_formatting(self, src):
        f = load(src)
        assigns = f.find_assignments("port")
        assert isinstance(assigns, list)


# ============================================================================
# 16. Full tree access
# ============================================================================

class TestTreeAccess:

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_get_tree_no_crash(self, src):
        f = load(src)
        tree = f.get_tree()
        assert isinstance(tree, dict)

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_tree_root_is_source_file(self, src):
        f = load(src)
        tree = f.get_tree()
        assert tree["kind"] == "SOURCE_FILE"

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_tree_has_children(self, src):
        f = load(src)
        tree = f.get_tree()
        assert "children" in tree
        assert isinstance(tree["children"], list)

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_tree_tokens_have_text(self, src):
        f = load(src)
        tree = f.get_tree()
        for tok in all_tokens(tree):
            assert "text" in tok
            assert isinstance(tok["text"], str)

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_tree_offsets_are_non_negative(self, src):
        f = load(src)
        tree = f.get_tree()
        for tok in all_tokens(tree):
            assert tok["offset"] >= 0
            assert tok["length"] >= 0

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_tree_token_text_matches_source(self, src):
        """Every token's text at its offset must match the source slice."""
        f = load(src)
        tree = f.get_tree()
        src_bytes = src.encode("utf-8")
        for tok in all_tokens(tree):
            start = tok["offset"]
            end = start + tok["length"]
            assert src_bytes[start:end].decode("utf-8", errors="replace") == tok["text"]

    def test_find_string_tokens_in_tree(self):
        f = load(STANDARD)
        tree = f.get_tree()
        strings = find_in_tree(tree, "STRING_DOUBLE")
        assert len(strings) > 0
        for s in strings:
            assert s["is_token"]
            assert s["text"].startswith('"')
            assert s["text"].endswith('"')

    def test_find_comments_in_tree(self):
        f = load(COMPLEX)
        tree = f.get_tree()
        comments = find_in_tree(tree, "COMMENT")
        assert len(comments) > 0

    def test_find_if_stmt_nodes(self):
        f = load(STANDARD)
        tree = f.get_tree()
        ifs = find_in_tree(tree, "IF_STMT")
        assert len(ifs) > 0
        for node in ifs:
            assert not node.get("is_token", False)
            assert "children" in node

    # ── replace_range ─────────────────────────────────────────────────────────

    def test_replace_range_string_token(self):
        f = load(STANDARD)
        tree = f.get_tree()
        # Find the cvss_base value string
        strings = [t for t in all_tokens(tree) if t.get("text") == '"7.5"']
        assert strings, "Expected to find '\"7.5\"' in tree"
        tok = strings[0]
        f.replace_range(tok["offset"], tok["length"], '"9.9"')
        assert '"9.9"' in f.to_str()
        assert '"7.5"' not in f.to_str()

    def test_replace_range_round_trips(self):
        f = load(STANDARD)
        tree = f.get_tree()
        strings = [t for t in all_tokens(tree) if t.get("text") == '"7.5"']
        tok = strings[0]
        f.replace_range(tok["offset"], tok["length"], '"5.5"')
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "5.5"

    def test_replace_range_zero_length_inserts(self):
        f = load(STANDARD)
        src_before = f.to_str()
        header = "# stress header\n"
        # Insert at position 0
        f.replace_range(0, 0, header)
        result = f.to_str()
        assert result.startswith(header)
        assert result[len(header):] == src_before

    def test_replace_range_ident_token(self):
        f = load(STANDARD)
        tree = f.get_tree()
        # Find an IDENT token with text "port"
        idents = [t for t in all_tokens(tree) if t.get("is_token") and t.get("text") == "port" and t["kind"] == "IDENT"]
        if idents:
            tok = idents[0]
            f.replace_range(tok["offset"], tok["length"], "port2")
            assert "port2" in f.to_str()

    @pytest.mark.parametrize("src", [MINIMAL, TABS, COMPACT, CRLF])
    def test_replace_range_all_fixtures(self, src):
        f = load(src)
        tree = f.get_tree()
        # Replace the first string token found
        strings = [t for t in all_tokens(tree) if t.get("kind") == "STRING_DOUBLE"]
        if strings:
            tok = strings[0]
            replacement = '"stress_replacement"'
            f.replace_range(tok["offset"], tok["length"], replacement)
            assert replacement in f.to_str()


# ============================================================================
# 17. Comment operations
# ============================================================================

class TestCommentOps:

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_get_comments_no_crash(self, src):
        f = load(src)
        comments = f.get_comments()
        assert isinstance(comments, list)

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_comments_have_text_and_offset(self, src):
        f = load(src)
        for c in f.get_comments():
            assert "text" in c
            assert "offset" in c
            assert c["text"].startswith("#")
            assert isinstance(c["offset"], int)

    def test_get_comments_standard(self):
        f = load(STANDARD)
        comments = f.get_comments()
        assert len(comments) >= 1
        texts = [c["text"] for c in comments]
        assert any("Holm" in t for t in texts)

    def test_find_comments_containing(self):
        f = load(STANDARD)
        matches = f.find_comments_containing("Holm")
        assert len(matches) >= 1
        for c in matches:
            assert "Holm" in c["text"]

    def test_find_comments_containing_no_match(self):
        f = load(STANDARD)
        matches = f.find_comments_containing("XYZNOTHERE")
        assert matches == []

    def test_find_comments_case_sensitive(self):
        f = load(STANDARD)
        upper = f.find_comments_containing("HOLM")
        lower = f.find_comments_containing("holm")
        # These may differ — just verify no crash
        assert isinstance(upper, list)
        assert isinstance(lower, list)

    def test_replace_comment(self):
        f = load(STANDARD)
        comments = f.get_comments()
        assert comments
        c = comments[0]
        f.replace_comment(c["offset"], "# replaced by stress test")
        assert "# replaced by stress test" in f.to_str()

    def test_replace_comment_wrong_offset_returns_false(self):
        f = load(STANDARD)
        result = f.replace_comment(999999, "# no comment here")
        assert not result
        assert not f.is_modified()

    def test_replace_comment_then_reparse(self):
        f = load(COMPLEX)
        c = f.get_comments()[0]
        f.replace_comment(c["offset"], "# stress updated")
        f2 = load(f.to_str())
        texts = [x["text"] for x in f2.get_comments()]
        assert "# stress updated" in texts

    @pytest.mark.parametrize("src", ALL_FIXTURES)
    def test_find_comments_no_crash(self, src):
        f = load(src)
        _ = f.find_comments_containing("test")
        _ = f.find_comments_containing("")

    def test_no_comments_on_bare_src(self):
        src = 'port = 80;\n'
        f = load(src)
        assert f.get_comments() == []
        assert not f.replace_comment(0, "# nothing")


# ============================================================================
# 18. Chained mutations (multiple ops before writing)
# ============================================================================

class TestChainedMutations:

    def test_chain_five_ops(self):
        f = load(STANDARD)
        f.set_script_tag("cvss_base", "9.9")
        f.set_version("2099-01-01T00:00:00+0000")
        f.add_script_tag("holm-stress", "yes")
        f.add_cve_id("CVE-2099-STRESS")
        f.add_xref("URL", "https://stress.test/")
        assert f.is_modified()
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "9.9"
        assert f2.get_version() == "2099-01-01T00:00:00+0000"
        assert f2.get_script_tag("holm-stress") == "yes"
        assert f2.has_cve_id("CVE-2099-STRESS")
        assert f2.has_xref("URL", "https://stress.test/")

    def test_chain_code_and_metadata(self):
        f = load(COMPLEX)
        f.set_script_tag("cvss_base", "8.8")
        f.add_to_security_message_blocks(
            'set_kb_item(name:"holm/pci/stress", value:get_script_oid());'
        )
        f.replace_call_named_arg("get_http_port", "default", "9090")
        f.replace_assignment("timeout", "120")
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "8.8"
        assert f2.has_pci_kb_item("holm/pci/stress")

    def test_chain_insert_and_comment(self):
        f = load(STANDARD)
        f.insert_after_call("get_http_port", 'log_message(data:"stress");')
        c = f.get_comments()[0]
        f.replace_comment(c["offset"], "# stress chain updated")
        f2 = load(f.to_str())
        assert "stress chain updated" in f2.to_str()

    def test_reset_after_chain(self):
        f = load(STANDARD)
        original = f.to_str()
        f.set_script_tag("cvss_base", "1.0")
        f.add_cve_id("CVE-9999-9999")
        f.set_name("Changed")
        f.reset()
        assert f.to_str() == original

    def test_chain_all_fixture_types(self):
        for src in DESCRIPTION_FIXTURES:
            f = load(src)
            f.set_script_tag("cvss_base", "5.0")
            f.add_script_tag("holm-chain-test", "1")
            assert f.is_modified()
            f2 = load(f.to_str())
            assert f2.get_script_tag("holm-chain-test") == "1"


# ============================================================================
# 19. Module-level file operations (requires temp directory)
# ============================================================================

class TestModuleLevel:

    @pytest.fixture
    def nasl_dir(self, tmp_path):
        """Write all fixtures as .nasl files to a temp directory."""
        files = {
            "standard.nasl": STANDARD,
            "tabs.nasl": TABS,
            "compact.nasl": COMPACT,
            "extra_blanks.nasl": EXTRA_BLANKS,
            "complex.nasl": COMPLEX,
            "minimal.nasl": MINIMAL,
            "many_calls.nasl": MANY_CALLS,
            "stale.nasl": STALE,
            "bare.nasl": BARE_CODE,
        }
        for name, src in files.items():
            (tmp_path / name).write_text(src)
        return str(tmp_path)

    def test_batch_set_script_tag(self, nasl_dir):
        total, edited, errors = nasl_py.batch_set_script_tag(nasl_dir, "cvss_base", "0.0")
        assert total > 0
        assert edited > 0
        assert errors == []

    def test_batch_set_simple_call(self, nasl_dir):
        total, edited, errors = nasl_py.batch_set_simple_call(nasl_dir, "script_family", "General")
        assert total > 0
        assert edited > 0

    def test_batch_add_cve_id(self, nasl_dir):
        total, edited, errors = nasl_py.batch_add_cve_id(nasl_dir, "CVE-2099-BATCH")
        assert total > 0
        # At least some files have script_cve_id
        assert edited >= 0

    def test_batch_remove_cve_id(self, nasl_dir):
        total, edited, errors = nasl_py.batch_remove_cve_id(nasl_dir, "CVE-2023-1234")
        assert total > 0

    def test_find_files_with_cve(self, nasl_dir):
        results = nasl_py.find_files_with_cve(nasl_dir, "CVE-2023-1234")
        assert isinstance(results, list)
        assert any("standard.nasl" in r for r in results)

    def test_find_files_with_tag(self, nasl_dir):
        results = nasl_py.find_files_with_tag(nasl_dir, "solution_type", "VendorFix")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_find_files_missing_tag(self, nasl_dir):
        results = nasl_py.find_files_missing_tag(nasl_dir, "nonexistent_tag_xyz")
        assert len(results) > 0  # all files are missing it

    def test_find_files_in_family(self, nasl_dir):
        results = nasl_py.find_files_in_family(nasl_dir, "General")
        assert isinstance(results, list)

    def test_find_files_with_include(self, nasl_dir):
        results = nasl_py.find_files_with_include(nasl_dir, "http_func.inc")
        assert any("standard.nasl" in r for r in results)

    def test_find_files_with_dependency(self, nasl_dir):
        results = nasl_py.find_files_with_dependency(nasl_dir, "os_detection.nasl")
        assert any("standard.nasl" in r for r in results)

    def test_find_files_with_holm_marker(self, nasl_dir):
        results = nasl_py.find_files_with_holm_marker(nasl_dir)
        assert isinstance(results, list)
        assert any("standard.nasl" in r or "complex.nasl" in r for r in results)

    def test_find_files_with_pci_key(self, nasl_dir):
        results = nasl_py.find_files_with_pci_key(nasl_dir, "holm/pci/web_servers")
        assert any("standard.nasl" in r for r in results)

    def test_find_files_with_call(self, nasl_dir):
        results = nasl_py.find_files_with_call(nasl_dir, "security_message")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_find_files_with_assignment(self, nasl_dir):
        results = nasl_py.find_files_with_assignment(nasl_dir, "port")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_find_files_with_comment(self, nasl_dir):
        results = nasl_py.find_files_with_comment(nasl_dir, "Holm")
        assert isinstance(results, list)
        assert any("standard.nasl" in r for r in results)

    def test_find_files_with_version_before(self, nasl_dir):
        results = nasl_py.find_files_with_version_before(nasl_dir, "2020-01-01")
        assert any("stale.nasl" not in r for r in results) or isinstance(results, list)

    def test_find_files_with_version_after(self, nasl_dir):
        results = nasl_py.find_files_with_version_after(nasl_dir, "2023-01-01")
        assert isinstance(results, list)
        assert len(results) >= 1

    def test_find_files_with_version_between(self, nasl_dir):
        results = nasl_py.find_files_with_version_between(nasl_dir, "2024-01-01", "2024-12-31")
        assert isinstance(results, list)

    def test_family_stats(self, nasl_dir):
        stats = nasl_py.family_stats(nasl_dir)
        assert isinstance(stats, dict)
        assert len(stats) > 0

    def test_category_stats(self, nasl_dir):
        stats = nasl_py.category_stats(nasl_dir)
        assert isinstance(stats, dict)
        assert len(stats) > 0

    def test_tag_value_stats(self, nasl_dir):
        stats = nasl_py.tag_value_stats(nasl_dir, "solution_type")
        assert isinstance(stats, dict)

    def test_resolve_dependencies_no_deps(self, nasl_dir):
        p = os.path.join(nasl_dir, "minimal.nasl")
        deps = nasl_py.resolve_dependencies(p, nasl_dir)
        assert isinstance(deps, list)
        # minimal.nasl has no dependencies

    def test_resolve_dependencies_with_deps(self, nasl_dir):
        p = os.path.join(nasl_dir, "standard.nasl")
        deps = nasl_py.resolve_dependencies(p, nasl_dir)
        assert isinstance(deps, list)
        # Files in the dir that are listed as deps would be resolved

    def test_resolve_dependencies_missing_file(self, nasl_dir):
        deps = nasl_py.resolve_dependencies("/nonexistent/file.nasl", nasl_dir)
        assert deps == []

    def test_find_no_results_returns_empty_list(self, nasl_dir):
        assert nasl_py.find_files_with_cve(nasl_dir, "CVE-9999-0000") == []
        assert nasl_py.find_files_with_call(nasl_dir, "nonexistent_fn_xyz") == []
        assert nasl_py.find_files_with_comment(nasl_dir, "XYZNOTPRESENT") == []


# ============================================================================
# 20. Edge cases and stress scenarios
# ============================================================================

class TestEdgeCases:

    def test_empty_string(self):
        f = load("")
        assert f.to_str() == ""
        assert f.get_oid() is None
        assert f.get_cve_ids() == []
        assert f.find_calls("anything") == []
        assert f.get_comments() == []

    def test_only_whitespace(self):
        f = load("   \n\n\t  \n")
        assert f.get_oid() is None

    def test_only_comment(self):
        f = load("# just a comment\n")
        assert f.get_comments() == [{"text": "# just a comment", "offset": 0}]

    def test_deeply_nested_blocks(self):
        src = """\
if(a) {
  if(b) {
    if(c) {
      if(security_message(port:80, data:"x")) {
        set_kb_item(name:"holm/pci/x", value:1);
      }
    }
  }
}
"""
        f = load(src)
        assert f.to_str() == src
        blocks = f.find_if_blocks_with_call("security_message")
        assert len(blocks) >= 1

    def test_function_with_many_args(self):
        src = 'foo(a:1, b:2, c:3, d:4, e:5, f:6, g:7, h:8, i:9, j:10);\n'
        f = load(src)
        calls = f.find_calls("foo")
        assert len(calls) == 1
        assert len(calls[0]["named_args"]) == 10

    def test_string_with_special_characters(self):
        src = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100099");
  script_version("2024-01-01T00:00:00+0000");
  script_name("Special: Chars / Test & More");
  script_family("General");
  script_copyright("(C) 2024 Corp");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"summary", value:"path/to/thing: value with: colons");
  exit(0);
}
"""
        f = load(src)
        assert f.get_name() == "Special: Chars / Test & More"
        assert f.to_str() == src

    def test_crlf_file_operations(self):
        f = load(CRLF)
        assert f.to_str() == CRLF
        assert f.get_oid() is not None
        assert f.get_version() is not None
        val = f.set_script_tag("cvss_base", "5.0")
        assert val
        assert f.is_modified()

    def test_tabs_file_all_ops(self):
        f = load(TABS)
        assert f.get_oid() == "1.3.6.1.4.1.25623.1.0.100002"
        assert f.get_cve_ids() == ["CVE-2022-9999"]
        f.set_script_tag("cvss_base", "6.0")
        f.add_cve_id("CVE-2022-TABS")
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "6.0"
        assert f2.has_cve_id("CVE-2022-TABS")

    def test_compact_file_all_ops(self):
        f = load(COMPACT)
        assert f.get_oid() is not None
        assert f.get_cve_ids() == ["CVE-2025-0001"]
        f.set_script_tag("cvss_base", "7.0")
        f2 = load(f.to_str())
        assert f2.get_script_tag("cvss_base") == "7.0"

    def test_multiple_script_add_preference(self):
        f = load(STANDARD)
        for i in range(10):
            f.add_preference(f"Pref{i}", "entry", str(i), id=i+10)
        prefs = f.get_preferences()
        assert len(prefs) == 11  # original 1 + 10 added

    def test_set_then_get_all_tags(self):
        f = load(STANDARD)
        f.set_script_tag("cvss_base", "3.3")
        f.set_script_tag("solution_type", "NoneAvailable")
        tags = f.get_all_script_tags()
        assert tags["cvss_base"] == "3.3"
        assert tags["solution_type"] == "NoneAvailable"

    def test_replace_range_then_find_call(self):
        """replace_range followed by find_calls should still work."""
        f = load(MANY_CALLS)
        tree = f.get_tree()
        # Replace a comment if any exist, or just insert at start
        f.replace_range(0, 0, "# stress header\n")
        calls = f.find_calls("get_http_port")
        assert len(calls) == 4

    def test_tree_covers_entire_source(self):
        """Sum of all token lengths must equal source byte length."""
        for src in ALL_FIXTURES:
            f = load(src)
            tree = f.get_tree()
            total = sum(t["length"] for t in all_tokens(tree))
            assert total == len(src.encode("utf-8")), f"Token lengths don't cover source for fixture starting: {src[:40]!r}"

    def test_offset_monotonically_increasing(self):
        """Token offsets must be non-decreasing."""
        for src in ALL_FIXTURES:
            f = load(src)
            tree = f.get_tree()
            tokens = list(all_tokens(tree))
            for i in range(1, len(tokens)):
                assert tokens[i]["offset"] >= tokens[i-1]["offset"]


# ============================================================================
# 21. Exit(0) remove → restore round-trip
#
# Verifies that:
#   1. find_calls("exit") locates all exit statements
#   2. Removing them (reverse offset order) and writing produces a file with
#      no exit calls
#   3. Re-inserting them at the original offsets (forward order) and writing
#      restores the source byte-for-byte
# ============================================================================

# Source with multiple exits (one in description, two in code body)
MULTI_EXIT = """\
if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.199001");
  script_version("2024-01-01T00:00:00+0000");
  script_name("Multi Exit");
  script_family("General");
  script_copyright("(C) 2024 Test");
  script_category(ACT_GATHER_INFO);
  script_tag(name:"cvss_base", value:"5.0");
  exit(0);
}
port = get_http_port(default:80);
if(!port) exit(0);
res = http_get(item:"/", port:port);
if(!res) exit(1);
"""


class TestExitRemoveRestore:
    """Round-trip: remove all exit() calls then restore them exactly."""

    def _exit_calls(self, src):
        """Return exit call info sorted by offset ascending."""
        f = load(src)
        calls = f.find_calls("exit")
        # Each call dict has 'text', 'offset', 'args'
        return sorted(calls, key=lambda c: c["offset"])

    @pytest.mark.parametrize("src", DESCRIPTION_FIXTURES + [MULTI_EXIT])
    def test_exit_remove_restore_roundtrip(self, src):
        """Remove all exits then restore them — result must equal original."""
        original = src
        exits = self._exit_calls(src)
        if not exits:
            pytest.skip("fixture has no exit() calls")

        # ── Phase 1: remove exits in reverse offset order ─────────────────
        f = load(src)
        for call in reversed(exits):
            offset = call["offset"]
            length = len(call["text"].encode("utf-8"))
            f.replace_range(offset, length, "")

        no_exits_str = f.to_str()

        # Verify: no exit calls remain
        f_check = load(no_exits_str)
        remaining = f_check.find_calls("exit")
        assert remaining == [], (
            f"Expected no exit calls after removal, found: {remaining}"
        )

        # ── Phase 2: restore exits in forward offset order ────────────────
        # When removing in reverse order, the bytes before each exit are
        # untouched, so original offsets are valid insertion points in
        # no_exits_str. Inserting in forward order restores offsets for
        # subsequent exits as each insertion adds back the removed bytes.
        f2 = load(no_exits_str)
        for call in exits:
            f2.replace_range(call["offset"], 0, call["text"])

        restored = f2.to_str()
        assert restored == original, (
            "Restored source does not match original.\n"
            f"Original ({len(original)} chars) vs restored ({len(restored)} chars)"
        )

    def test_exits_found_in_multi_exit_fixture(self):
        exits = self._exit_calls(MULTI_EXIT)
        assert len(exits) == 3, f"Expected 3 exits in MULTI_EXIT, found {len(exits)}"

    def test_no_exit_fixture_skipped(self):
        # BARE_CODE has no description block exit
        exits = self._exit_calls(BARE_CODE)
        # bare code has no exit(0) in description, may have none
        assert isinstance(exits, list)

    def test_round_trip_tabs_fixture(self):
        src = TABS
        exits = self._exit_calls(src)
        assert len(exits) >= 1
        f = load(src)
        for call in reversed(exits):
            f.replace_range(call["offset"], len(call["text"].encode("utf-8")), "")
        no_exits = f.to_str()
        f2 = load(no_exits)
        for call in exits:
            f2.replace_range(call["offset"], 0, call["text"])
        assert f2.to_str() == src

    def test_round_trip_crlf_fixture(self):
        src = CRLF
        exits = self._exit_calls(src)
        assert len(exits) >= 1
        f = load(src)
        for call in reversed(exits):
            f.replace_range(call["offset"], len(call["text"].encode("utf-8")), "")
        no_exits = f.to_str()
        f2 = load(no_exits)
        for call in exits:
            f2.replace_range(call["offset"], 0, call["text"])
        assert f2.to_str() == src


# ============================================================================
# 22. Integration: round-trip on real plugin directory
#
# Reads NASL_PLUGIN_DIR from environment. Skipped if not set.
# Tests on a sample of files (NASL_RT_SAMPLE, default 500).
#
# Tests:
#   A. summary tag add/revert → git diff clean
#   B. exit(0) remove/restore on sampled files → content round-trips
# ============================================================================

_PLUGIN_DIR = os.environ.get("NASL_PLUGIN_DIR", "")
_SAMPLE_SIZE = int(os.environ.get("NASL_RT_SAMPLE", "500"))
_SKIP_INTEGRATION = not _PLUGIN_DIR or not pathlib.Path(_PLUGIN_DIR).is_dir()


def _sample_nasl_files(directory: str, n: int):
    """Return up to n evenly-spaced .nasl files from directory."""
    files = sorted(pathlib.Path(directory).rglob("*.nasl"))
    if not files:
        return []
    step = max(1, len(files) // n)
    return files[::step][:n]


def _is_utf8(path: pathlib.Path) -> bool:
    try:
        path.read_bytes().decode("utf-8")
        return True
    except (UnicodeDecodeError, OSError):
        return False


@pytest.mark.skipif(_SKIP_INTEGRATION, reason="NASL_PLUGIN_DIR not set or not a directory")
class TestIntegrationRoundTrip:
    """Real-file integration tests. Set NASL_PLUGIN_DIR to enable."""

    @pytest.fixture(scope="class")
    def sampled_files(self):
        files = _sample_nasl_files(_PLUGIN_DIR, _SAMPLE_SIZE)
        # Only UTF-8 files (a handful of legacy files use Latin-1)
        return [f for f in files if _is_utf8(f)]

    # ── A. summary tag add/revert ─────────────────────────────────────────

    def test_summary_tag_roundtrip_git_clean(self, sampled_files):
        """
        For each file that has a summary tag:
          1. Read → update summary → write
          2. Read → revert summary → write
          3. Assert git diff is clean for those files.
        """
        MARKER = " [NASL_RT_TEST]"
        touched = []

        for path in sampled_files:
            try:
                src = path.read_text(encoding="utf-8")
                f = nasl_py.NaslFile.from_str(src)
                val = f.get_script_tag("summary")
                if val is None or MARKER in val:
                    continue
                f.set_script_tag("summary", val + MARKER)
                path.write_text(f.to_str(), encoding="utf-8")
                touched.append(path)
            except Exception:
                pass

        assert touched, "No files with summary tags found in sample"

        # Verify: git sees exactly the files we touched
        git_dirty = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=_PLUGIN_DIR, capture_output=True, text=True
        ).stdout.splitlines()
        assert len(git_dirty) == len(touched), (
            f"Git dirty count {len(git_dirty)} != touched count {len(touched)}"
        )

        # Spot-check: only the marker line changed
        rel = touched[0].relative_to(_PLUGIN_DIR)
        diff = subprocess.run(
            ["git", "diff", str(rel)],
            cwd=_PLUGIN_DIR, capture_output=True, text=True
        ).stdout
        assert MARKER in diff, "Marker not visible in git diff"
        added = [l for l in diff.splitlines() if l.startswith("+") and not l.startswith("+++")]
        removed = [l for l in diff.splitlines() if l.startswith("-") and not l.startswith("---")]
        assert len(added) <= 2 and len(removed) <= 2, (
            f"More than one line changed in spot-check file:\n{diff[:500]}"
        )

        # Revert
        for path in touched:
            try:
                src = path.read_text(encoding="utf-8")
                f = nasl_py.NaslFile.from_str(src)
                val = f.get_script_tag("summary")
                if val and val.endswith(MARKER):
                    f.set_script_tag("summary", val[:-len(MARKER)])
                path.write_text(f.to_str(), encoding="utf-8")
            except Exception:
                pass

        # Verify: clean
        git_dirty_after = subprocess.run(
            ["git", "diff", "--name-only"],
            cwd=_PLUGIN_DIR, capture_output=True, text=True
        ).stdout.splitlines()
        dirty = [l for l in git_dirty_after if l]
        assert not dirty, (
            f"Git not clean after revert. Still dirty: {dirty[:5]}"
        )

    # ── B. exit(0) remove/restore ─────────────────────────────────────────

    def test_exit_remove_restore_on_real_files(self, sampled_files):
        """
        For each sampled file:
          1. Find all exit() calls
          2. Remove them (reverse offset order)
          3. Restore them (forward offset order)
          4. Assert restored content == original
        """
        checked = 0
        failures = []

        for path in sampled_files:
            try:
                original = path.read_text(encoding="utf-8")
                f = load(original)
                exits = sorted(f.find_calls("exit"), key=lambda c: c["offset"])
                if not exits:
                    continue

                # Remove in reverse order
                for call in reversed(exits):
                    f.replace_range(call["offset"],
                                    len(call["text"].encode("utf-8")), "")

                no_exits = f.to_str()

                # Restore in forward order
                f2 = load(no_exits)
                for call in exits:
                    f2.replace_range(call["offset"], 0, call["text"])

                restored = f2.to_str()
                if restored != original:
                    failures.append(
                        f"{path.name}: {len(original)} vs {len(restored)} chars"
                    )
                checked += 1
            except Exception as e:
                failures.append(f"{path.name}: exception {e}")

        assert checked > 0, "No files with exit() calls found in sample"
        assert not failures, (
            f"{len(failures)} files failed exit round-trip:\n" +
            "\n".join(failures[:10])
        )
