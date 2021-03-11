# Application Signature Verification<a name="EN-US_TOPIC_0000001121676905"></a>

To ensure the integrity and trustworthiness of the applications to be installed in OpenHarmony, the applications must be signed and their signatures must be verified.

In application development: After developing an application, you need to sign its installation package to ensure that the installation package is not tampered with when it is released on devices. To sign the application package, you can use the signature tools and the public key certificates and follow the signing certificate generation specifications provided by the application integrity verification module. For your convenience, a public key certificate and a corresponding private key are preset in OpenHarmony. You need to replace the public key certificate and private key in your commercial version of OpenHarmony.

In application installation: the application framework subsystem of OpenHarmony installs applications. Upon receiving the application installation package, the application framework subsystem parses the signature of the installation package, and verifies the signature using the APIs provided by the application integrity verification module. The application can be installed only after the verification succeeds. The application integrity verification module uses the preset public key certificate to verify the signature.

