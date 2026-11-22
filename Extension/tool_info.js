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
          ],
          note: "This example uses a domain, but the same explanation applies to IP address and URL results. The values may differ depending on the indicator being analyzed."
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
  
  // IPQS info
  ipqs: {
      title: "About IPQualityScore",
      sections: [
          {
              heading: "What is IPQualityScore?",
              paragraphs: [
                  "IPQualityScore (IPQS) is a service that checks links for signs of potentially unsafe or suspicious activity.",
                  "It looks for warning signs that a website may be connected to scams, phishing, or malware."
              ]
          },
          {
              heading: "How does PhishCatcher use it?",
              paragraphs: [
                  "When you analyze an email, PhishCatcher sends the links found in the message to IPQualityScore for analysis.",
                  "IPQS checks each link and returns information that can help you understand whether it may be risky."
              ]
          },
          {
              heading: "How do I read the results?",
              paragraphs: [
                  "IPQualityScore provides several results to help you understand the link:"
              ],
              definitions: [
                  {
                      term: "Safe",
                      meaning: "Indicates whether IPQS considers the link safe based on its analysis. A safe result does not guarantee that the website is harmless."
                  },
                  {
                      term: "Suspicious",
                      meaning: "Indicates whether IPQS found signs that the link may be connected to suspicious activity."
                  },
                  {
                      term: "Domain",
                      meaning: "The website name associated with the link's destination."
                  },
                  {
                      term: "Malware",
                      meaning: "Indicates whether the link is associated with harmful software that could affect a device."
                  },
                  {
                      term: "Phishing",
                      meaning: "Indicates whether the link may lead to a website designed to trick people into sharing personal information, such as passwords."
                  },
                  {
                      term: "Risk Score",
                      meaning: "A score from 0 to 100 that estimates how risky a link may be. A higher score means IPQS sees more signs of risk. Scores of 85 or higher are considered high risk by IPQS."
                  },
                  {
                      term: "Domain Age",
                      meaning: "How long the website's domain has been registered. A newly registered domain may deserve extra attention, but its age alone does not mean it is unsafe."
                  }
              ],
              paragraphsAfterDefinitions: [
                  "Look at these results together rather than relying on just one of them."
              ]
          },
          {
              heading: "Let's look at an example",
              example: {
                  description: "Imagine an email contains a link to example.com. IPQualityScore analyzes the link and returns these results:",
                  total: 0,
                  results: [
                      { label: "Safe", count: "Yes" },
                      { label: "Suspicious", count: "No" },
                      { label: "Domain", count: "example.com" },
                      { label: "Malware", count: "No" },
                      { label: "Phishing", count: "No" },
                      { label: "Risk Score", count: 12 },
                      { label: "Domain Age", count: "18 years ago" }
                  ],
                  steps: [
                      "The link is marked as safe and is not flagged as suspicious.",
                      "IPQS did not identify signs of malware or phishing.",
                      "The risk score is 12, which is below IPQS's high-risk threshold of 85.",
                      "The domain has been registered for 18 years. This gives us additional context, but does not prove that the website is safe."
                  ],
                  note: "This is an example to help explain the results. Actual results may differ depending on the link being analyzed."
              }
          },
          {
              heading: "Things to keep in mind",
              paragraphs: [
                  "IPQualityScore provides warning signs, not a guarantee that a website is safe or harmful.",
                  "A low risk score does not guarantee that a link is safe. A high score means the link deserves closer attention.",
                  "A website's age is only one clue. Both new and older websites can be used for harmful activity."
              ]
          }
      ]
  },

  // AbuseIPDB info
  abuseipdb: {
    title: "About AbuseIPDB",
  
    sections: [
      {
        heading: "What is AbuseIPDB?",
        paragraphs: [
          "AbuseIPDB is an online service that collects and shares reports about IP addresses associated with abusive activity, such as spam, hacking attempts, and other suspicious behavior.",
          "It allows users and security professionals to check whether an IP address has previously been reported for potentially harmful activity."
        ]
      },
      {
        heading: "How does PhishCatcher use it?",
        paragraphs: [
          "When you analyze an email, PhishCatcher extracts IP addresses from its email headers.",
          "It filters out non-public IP addresses and checks the remaining public IP addresses against AbuseIPDB's existing records.",
          "PhishCatcher retrieves information such as the Abuse Confidence Score, Total Reports, country, ISP, and whitelist status. It looks up existing information; it does not submit abuse reports."
        ]
      },
      {
        heading: "How do I read the results?",
        paragraphs: [
          "Each result provides information about the IP address and its history in AbuseIPDB."
        ],
        definitions: [
          {
            term: "Abuse Confidence Score",
            meaning: "A score from 0 to 100 based on reports submitted about an IP address. A higher score indicates greater concern about reported abusive activity, not the probability that the IP address is malicious."
          },
          {
            term: "Total Reports",
            meaning: "The number of abuse reports submitted about this IP address and recorded by AbuseIPDB."
          },
          {
            term: "Country",
            meaning: "The country associated with the IP address. This does not necessarily tell us where the person who sent the email is located."
          },
          {
            term: "ISP (Internet Service Provider)",
            meaning: "The organization that provides or manages the internet connection associated with the IP address. For example, this could be an internet provider, university, or hosting company."
          },
          {
            term: "Whitelisted",
            meaning: "Indicates whether AbuseIPDB has marked the IP address as trusted. Yes means it is on the whitelist, while No means it is not. A whitelisted IP address is not automatically guaranteed to be safe."
          }
        ]
      },
      {
        heading: "Let's look at an example",
        example: {
          description: "Imagine PhishCatcher returns the following results for the IP address 192.0.2.10:",
          total: 0,
          results: [
            { label: "Abuse Confidence Score", count: 75 },
            { label: "Total Reports", count: 12 },
            { label: "Country", count: "US" },
            { label: "ISP", count: "Example University" },
            { label: "Whitelisted", count: "No" }
          ],
          steps: [
            "Start with the Abuse Confidence Score: A score of 75 indicates considerable concern about reported abusive activity associated with this IP address.",
            "Look at Total Reports: The IP address has 12 abuse reports recorded by AbuseIPDB.",
            "Check the Country: The IP address is associated with the United States.",
            "Look at the ISP: Example University is listed as the organization associated with the IP address.",
            "Check Whitelisted: The result is No, meaning AbuseIPDB has not marked this IP address as trusted.",
            "Consider all the results together: The score and report history suggest the IP address deserves further investigation, but they do not prove that the email is malicious."
          ]
        }
      },
      {
        heading: "Things to keep in mind",
        paragraphs: [
          "AbuseIPDB relies on reports submitted by users. Reports may vary in accuracy and can become outdated.",
          "An IP address may be shared by multiple websites, services, organizations, or users. A report does not necessarily mean the current owner or sender is responsible for the activity.",
          "A score of zero or no reports does not guarantee that an IP address is safe.",
          "AbuseIPDB results are one source of threat intelligence and should be considered alongside the other findings in PhishCatcher."
        ]
      }
    ]
  }  
};
