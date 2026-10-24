// Plain text is intended in this example.
export function renderPreview(req, element) {
  const userInput = req.body.content;
  element.textContent = userInput;
}
