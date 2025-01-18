# Growing Footprint

The average security footprint is increasing rapidly as companies not only adopt cloud and on-prem hybrid strategies, but also as personal devices become ubiquitous — and more mobile. Any strategy that focuses on only one portion of the footprint is dubious at best.

Web assets have been adopted as important asset targets for testing in recent years, as have hosts (essentially anything with an IP address). But what about mobile devices? Are they getting the attention they need to manage that ever-increasing footprint and shore up the weaker, more vulnerable areas of corporations’ risk footprints? And how do you prevent your mobile apps from being hacked, through APIs, web, or cloud vectors?

This is an area that needs more attention. The goal of this article is to both make our customers and prospects more aware of these risks as well as to direct our Synack Red Team (SRT) to broaden their skills to better cover mobile assets.

---

## Why Test Mobile?

For those researchers who haven’t spent a lot of time testing mobile applications, learning mobile might not be as much of a change as you’d expect; and it’s a great way to improve your skills. Most applications are extensions of the same web application you’ve already been testing. Knowing one (web) often allows you to be familiar with the other (mobile) due to the fact that applications often share the same API, OAuth mechanisms, SQL backends, session cookies, etc.

If this isn’t enticing enough, most mobile listings will reward your report at **twice (2x)** the market value for a report that requires the application to be directly patched by the vendor. You’ll be able to continue your research even when you aren’t online; a mobile application can often be deconstructed to its original source code quite easily, and there are a lot of tools freely and readily available.

---

## What to Expect

When diving into mobile testing, here are some key points to consider:

- **Emulation**: On Android, there is no physical device required. A freely available emulator and tools suffice. For iOS, a physical jailbroken device is recommended.
- **Tools**: JSON remains dominant for testing, and Burp Suite is still the tool of choice.
- **Languages**: Mobile apps often use Java, Kotlin, or Swift, which are easier to analyze than minified JavaScript.
- **App Types**: Applications may be native, hybrid, or fully web-based but still share many common vulnerabilities.

---

## Types of Vulnerabilities

Mobile testing involves identifying a variety of vulnerabilities, including:

- Task hijacking
- Insecure component configurations
- Cryptography implementation flaws
- API weaknesses
- OAuth manipulation
- Cross-site scripting (XSS)
- SQL Injection
- Multi-factor authentication bypasses (MFA)
- Access and privacy violations (e.g., IDORs)
- Sensitive data disclosures
- Remote Code Executions
- Privilege Escalations

…and many more.

---

## Android Testing

### Setting up Your Environment
1. **Install Android Studio**: Comes with an emulator capable of mimicking production Android devices.
2. **Install HAXM**: Intel x86 Emulator Accelerator for better performance.
3. **Configure an Emulator**:
    - Choose hardware (e.g., a phone with Play Store capabilities).
    - Opt for Android 9.0 / API Level 28 to allow full root and system writable access.

### Proxying Traffic with Burp Suite
- **Intercept Traffic**: Configure the emulator to proxy traffic through Burp Suite.
- **Bypass Certificate Pinning**: Use tools like Frida or Objection to bypass app-level SSL pinning.

---

## iOS Testing

### Environment Setup
1. **Install XCode**: Required for development and deployment on iOS devices.
2. **Jailbreaking**: Optional but useful for bypassing security measures like certificate pinning.

### Proxying Traffic
- Configure your iOS device to use Burp Suite as a proxy.
- Install SSL Kill Switch 2 or use Frida scripts to bypass SSL pinning.

---

## Common Tools and Techniques

### Tools
- **Frida**: Dynamic instrumentation for runtime modifications.
- **Objection**: A user-friendly interface for Frida.
- **MobSF**: Automated static and dynamic analysis tool for mobile applications.

### Techniques
- **Decompile and Analyze**: Use tools like JADX for Android or Ghidra for iOS to reverse-engineer applications.
- **Static Analysis**: Look for hardcoded credentials, cryptographic keys, and insecure configurations.
- **Dynamic Analysis**: Test app functionality using proxies and emulators.

---

## Conclusion

Congratulations! You’re now on your way to mobile testing and can leverage your existing web skills to explore this new avenue. By understanding the risks associated with mobile applications, you can significantly contribute to managing and securing the ever-growing security footprint.

For any questions or further assistance, feel free to reach out to the Synack Red Team community.

---

