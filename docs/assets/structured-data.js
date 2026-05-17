(function () {
  if (document.querySelector('script[type="application/ld+json"][data-ceres-schema]')) {
    return;
  }

  var schema = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "WebSite",
        "@id": "https://duriantaco.github.io/ceres/#website",
        "name": "Ceres",
        "url": "https://duriantaco.github.io/ceres/",
        "description": "Static pre-production AI security scanner documentation."
      },
      {
        "@type": "SoftwareApplication",
        "@id": "https://duriantaco.github.io/ceres/#software",
        "name": "Ceres",
        "applicationCategory": "SecurityApplication",
        "operatingSystem": "Python 3.10+",
        "description": "Static AI security scanner for models, datasets, RAG, prompts, agents, tools, MCP, and AI supply chain.",
        "url": "https://duriantaco.github.io/ceres/",
        "codeRepository": "https://github.com/duriantaco/ceres",
        "license": "https://www.apache.org/licenses/LICENSE-2.0",
        "offers": {
          "@type": "Offer",
          "price": "0",
          "priceCurrency": "USD"
        }
      },
      {
        "@type": "SoftwareSourceCode",
        "@id": "https://github.com/duriantaco/ceres#source",
        "name": "Ceres",
        "codeRepository": "https://github.com/duriantaco/ceres",
        "programmingLanguage": "Python",
        "runtimePlatform": "Python 3.10+",
        "license": "https://www.apache.org/licenses/LICENSE-2.0"
      }
    ]
  };

  var script = document.createElement("script");
  script.type = "application/ld+json";
  script.setAttribute("data-ceres-schema", "true");
  script.text = JSON.stringify(schema);
  document.head.appendChild(script);
})();
