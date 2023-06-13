// See https://aka.ms/new-console-template for more information

using System.Security.Cryptography;

var rsaKey = RSA.Create();
var privateKey = rsaKey.ExportRSAPrivateKey();
File.WriteAllBytes("key",privateKey);