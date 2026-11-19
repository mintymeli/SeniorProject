const toolInfo = {
  virustotal: {
    title: "About VirusTotal",

    sections: [
      {
        heading: "What is VirusTotal?",
        paragraphs: [
          "VirusTotal is an online service that helps identify potentially harmful websites, IP addresses, files, and other digital content.",
          "It gathers results from many different security companies and their tools so users can see what those tools have found in one place."
        ],
        definitions: [
          {
            term: "Vendor",
            meaning: "A security company or service that provides tools to identify potential threats."
          },
          {
            term: "Report",
            meaning: "A record containing the results of security checks performed on an indicator, such as a domain or IP address."
          },
          {
            term: "Detection",
            meaning: "When a security tool identifies or flags something as potentially harmful or suspicious."
          }
        ]
      },

      {
        heading: "How does PhishCatcher use it?",
        paragraphs: [
          "When you analyze an email, PhishCatcher extracts domains and public IP addresses from its email headers.",
          "It then checks VirusTotal for existing reports on those indicators to see whether security tools have previously identified potentially harmful or suspicious activity.",
          "This provides additional information about the websites and servers involved in delivering an email, helping users recognize indicators that may deserve further investigation."
        ]
      },

      {
        heading: "How do I read the results?",
        paragraphs: [
          "VirusTotal displays how many security tools assigned each classification to the domain or IP address being checked."
        ],
        definitions: [
          {
            term: "Malicious",
            meaning: "The number of security tools that identified the indicator as associated with harmful activity."
          },
          {
            term: "Suspicious",
            meaning: "The number of security tools that flagged the indicator as potentially concerning, but did not classify it as malicious."
          },
          {
            term: "Harmless",
            meaning: "The number of security tools that classified the indicator as harmless. This does not guarantee that it is completely safe."
          },
          {
            term: "Undetected",
            meaning: "The number of security tools that did not identify a threat. This does not necessarily mean the indicator is safe."
          }
        ],        
        paragraphsAfterDefinitions: [
        "A vendor fraction shows how many vendors gave a particular classification compared with the total number of vendors included in the analysis.",
        ]

      },

      {
        heading: "Let's look at an example",

        example: {
          description: "Imagine PhishCatcher returns these results for a domain:",
          total: 92,
          results: [
            { label: "Malicious", count: 5 },
            { label: "Suspicious", count: 3 },
            { label: "Harmless", count: 60 },
            { label: "Undetected", count: 20 }
          ],
          steps: [
            "Start with the total: 92 vendors are included in this analysis.",
            "Look at Malicious: 5 vendors identified the domain as associated with harmful activity.",
            "Look at Suspicious: 3 vendors flagged the domain as potentially concerning.",
            "Look at Harmless: 60 vendors classified the domain as harmless.",
            "Look at Undetected: 20 vendors did not identify a threat.",
            "Consider all the results together. The 5 malicious detections are worth investigating, even though many other vendors did not flag the domain."
          ]
        }
      },

      {
        heading: "Things to keep in mind",
        paragraphs: [
          "Different security vendors may reach different conclusions about the same indicator.",
          "Reports may be incomplete or outdated, so the results may not reflect the indicator's current activity.",
          "Zero detections does not guarantee that a domain or IP address is safe.",
          "A detection is a reason to investigate further, not proof by itself that an email is malicious."
        ]
      }
    ],

    disclosure: {
      heading: "Disclosure",
      text: "The total number of vendors includes all vendors whose results are part of the analysis, including those that did not provide a malicious, suspicious, harmless, or undetected classification. Because of this, the four category counts may not add up to the total."
    }
  },
};
