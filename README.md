# TokenCredentialHttpMessageHandler

An `HttpMessageHandler` that uses a `Azure.Identity.TokenCredential` to acquire access tokens and add them to outgoing HTTP requests.

## Usage

```csharp
HttpClient client = new(new TokenCredentialHttpMessageHandler(new DefaultAzureCredential(), ["<scope>"]));
```
