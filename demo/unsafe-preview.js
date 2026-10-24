// Demonstration only. Do not deploy this example.
export function renderPreview(req, element) {
  const userInput = req.body.content;
  element.innerHTML = userInput;
}
