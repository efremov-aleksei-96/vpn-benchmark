"""Strict single-pass substitution of placeholders in trusted CI templates."""
import re

TOKEN=re.compile(r'__[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)*__')

def render_template(template,values):
    # Validate delimiters in the SOURCE, never in generated credential values.
    # The substitution callback is single-pass: inserted values remain opaque.
    if '__' in TOKEN.sub('',template):
        raise ValueError('malformed template delimiter')
    tokens=set(TOKEN.findall(template))
    if not tokens.issubset(values):
        raise ValueError('unknown template placeholder')
    if any(not isinstance(values[k],str) or not values[k] for k in tokens):
        raise ValueError('missing template value')
    return TOKEN.sub(lambda m: values[m.group()],template)
