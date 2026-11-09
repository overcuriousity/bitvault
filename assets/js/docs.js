// Starts the vendored Swagger UI (loaded as a classic script before this module) on the spec.
const root = document.getElementById("swagger-ui");
if (root && window.SwaggerUIBundle) {
  window.SwaggerUIBundle({
    url: root.dataset.specUrl,
    domNode: root,
    presets: [window.SwaggerUIBundle.presets.apis],
    layout: "BaseLayout",
    deepLinking: true,
  });
}
