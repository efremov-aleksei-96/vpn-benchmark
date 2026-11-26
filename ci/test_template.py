import json,pathlib,unittest
from template import render_template

class TemplateTests(unittest.TestCase):
    def test_double_underscore_in_secret(self):
        self.assertEqual(render_template('{"password":"__PASS__"}',{'__PASS__':'abc__def_-'}),'{"password":"abc__def_-"}')
    def test_opaque_not_recursive(self):
        self.assertEqual(render_template('__PASS__ __OTHER__',{'__PASS__':'__OTHER__','__OTHER__':'x'}),'__OTHER__ x')
    def test_unknown(self):
        with self.assertRaises(ValueError):render_template('__UNKNOWN__',{})
    def test_malformed(self):
        for value in ('__lower__','__BROKEN','BROKEN__','____','__A-B__'):
            with self.subTest(value=value),self.assertRaises(ValueError):render_template(value,{})
    def test_missing_empty(self):
        for value in ('',None):
            with self.subTest(value=value),self.assertRaises(ValueError):render_template('__PASS__',{'__PASS__':value})
    def test_actual_templates(self):
        values={'__PUBLIC_IPV4__':'198.18.254.1','__WAN_IF__':'vb-wan',
                '__TESTER_IPV4_CIDRS__':'198.18.254.2/32','__VLESS_UUID__':'00000000-0000-4000-8000-000000000001',
                '__REALITY_HOST__':'example.com','__REALITY_PRIVATE_KEY__':'synthetic__key',
                '__REALITY_SHORT_ID__':'0011223344556677','__NAIVE_PASSWORD__':'synthetic__naive',
                '__MIERU_PASSWORD__':'synthetic__mieru'}
        src=pathlib.Path(__file__).resolve().parents[1]/'candidate'
        s=json.loads(render_template((src/'sing-box.json').read_text(),values))
        m=json.loads(render_template((src/'mita.json').read_text(),values))
        self.assertEqual(s['inbounds'][0]['tls']['reality']['private_key'],values['__REALITY_PRIVATE_KEY__'])
        self.assertEqual(s['inbounds'][1]['users'][0]['password'],values['__NAIVE_PASSWORD__'])
        self.assertEqual(m['users'][0]['password'],values['__MIERU_PASSWORD__'])
        f=render_template((src/'firewall.nft').read_text(),values)
        self.assertNotIn('__',f)
        self.assertIn('198.18.254.2/32',f)
        self.assertIn('0x40000000',f)

if __name__=='__main__':unittest.main(verbosity=2)
