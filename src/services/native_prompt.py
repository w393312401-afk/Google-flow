"""Read native prompt text without CSS paragraph spacing or whitespace folding."""


_READ_PROMPT = r"""(editor) => {
    // Chromium's contenteditable fill inserts one p/div per input line. innerText
    // adds display-only paragraph spacing, while textContent loses every break.
    // Read those line boundaries explicitly; preserve all actual text verbatim.
    const blocks = new Set(['P', 'DIV']);
    const inline = new Set(['SPAN', 'B', 'STRONG', 'I', 'EM', 'U', 'S', 'MARK', 'CODE']);
    let valid = true;
    function readInline(node) {
        if (node.nodeType === Node.TEXT_NODE) return node.nodeValue;
        if (node.nodeType !== Node.ELEMENT_NODE) { valid = false; return ''; }
        if (node.tagName === 'BR') {
            return node.classList.contains('ProseMirror-trailingBreak') ? '' : '\n';
        }
        // Unknown content (including reference chips) must not silently vanish.
        if (!inline.has(node.tagName) || node.contentEditable === 'false') {
            valid = false; return '';
        }
        return Array.from(node.childNodes, readInline).join('');
    }
    function readBlock(node) {
        const children = Array.from(node.childNodes);
        // A sole BR is the caret placeholder in an empty contenteditable block.
        if (children.length === 1 && children[0].nodeName === 'BR') return '';
        return children.map(readInline).join('');
    }
    const lines = [];
    let pending = '', hasInline = false;
    for (const node of editor.childNodes) {
        if (node.nodeType === Node.ELEMENT_NODE && blocks.has(node.tagName)) {
            if (node.contentEditable === 'false') { valid = false; break; }
            if (hasInline) { lines.push(pending); pending = ''; hasInline = false; }
            lines.push(readBlock(node));
        } else {
            hasInline = true;
            pending += readInline(node);
        }
    }
    if (hasInline) lines.push(pending);
    return valid ? lines.join('\n') : null;
}"""


async def read_native_prompt(editor) -> str | None:
    """Return exact editor text, or None for an unsupported editor structure.

    This is only a pre-submit UI check. The native video RPC still independently
    compares its unmodified prompt to the caller's original prompt byte for byte.
    """
    return await editor.evaluate(_READ_PROMPT, timeout=4000)
