import React, { useState, useEffect } from "react";
import {
  View, Text, TextInput, Button, ScrollView, StyleSheet, Alert,
} from "react-native";

import { generateKeypair } from "./crypto";
import {
  storePrivateKey, storeLaptopPublicKey, getStoredPublicKey,
  checkBiometricsAvailable, clearAll,
} from "./secureStore";

export default function PairingScreen({ onPaired }) {
  const [myPublicKey, setMyPublicKey] = useState(null);
  const [laptopKeyInput, setLaptopKeyInput] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    getStoredPublicKey().then(setMyPublicKey);
  }, []);

  async function handleGenerateKeypair() {
    const available = await checkBiometricsAvailable();
    if (!available) {
      Alert.alert(
        "No biometrics set up",
        "Set up Face ID / fingerprint in your phone's settings first — " +
          "this app refuses to store an unlock key without a biometric gate."
      );
      return;
    }

    setBusy(true);
    try {
      const { publicKeyPem, privateKeyPem } = generateKeypair();
      await storePrivateKey(privateKeyPem, publicKeyPem);
      setMyPublicKey(publicKeyPem);
    } finally {
      setBusy(false);
    }
  }

  async function handleSaveLaptopKey() {
    if (!laptopKeyInput.includes("BEGIN PUBLIC KEY")) {
      Alert.alert("That doesn't look like a valid PEM public key.");
      return;
    }
    await storeLaptopPublicKey(laptopKeyInput.trim() + "\n");
    Alert.alert("Saved", "Laptop identity stored. Pairing complete.");
    onPaired && onPaired();
  }

  async function handleReset() {
    Alert.alert(
      "Reset pairing?",
      "This deletes your key on this phone. You'll need to re-pair with " +
        "the laptop (running pair.py again there too).",
      [
        { text: "Cancel", style: "cancel" },
        {
          text: "Reset", style: "destructive",
          onPress: async () => {
            await clearAll();
            setMyPublicKey(null);
            setLaptopKeyInput("");
          },
        },
      ]
    );
  }

  return (
    <ScrollView style={styles.container} contentContainerStyle={styles.content}>
      <Text style={styles.title}>Pair with your laptop</Text>

      <Text style={styles.step}>Step 1 — Install the laptop's certificate</Text>
      <Text style={styles.body}>
        On the laptop, run pair.py. It writes ca-cert.pem. Transfer that
        file to this phone (AirDrop, email, USB — it's not secret) and
        install it as a trusted certificate in your phone's Settings before
        continuing. Instructions are printed by pair.py.
      </Text>

      <Text style={styles.step}>Step 2 — Generate this phone's key</Text>
      {!myPublicKey ? (
        <Button
          title={busy ? "Generating..." : "Generate keypair"}
          onPress={handleGenerateKeypair}
          disabled={busy}
        />
      ) : (
        <View>
          <Text style={styles.body}>
            Your phone's public key (paste this into pair.py when it asks):
          </Text>
          <Text selectable style={styles.mono}>{myPublicKey}</Text>
        </View>
      )}

      {myPublicKey && (
        <View style={styles.section}>
          <Text style={styles.step}>Step 3 — Enter the laptop's public key</Text>
          <Text style={styles.body}>
            pair.py printed this on the laptop's screen. Paste the whole
            block, including the BEGIN/END lines.
          </Text>
          <TextInput
            style={styles.input}
            multiline
            numberOfLines={8}
            value={laptopKeyInput}
            onChangeText={setLaptopKeyInput}
            placeholder="-----BEGIN PUBLIC KEY-----..."
            autoCapitalize="none"
            autoCorrect={false}
          />
          <Button title="Save and finish pairing" onPress={handleSaveLaptopKey} />
        </View>
      )}

      <View style={styles.section}>
        <Button title="Reset pairing" color="#c0392b" onPress={handleReset} />
      </View>
    </ScrollView>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: "#fff" },
  content: { padding: 20, paddingTop: 60 },
  title: { fontSize: 24, fontWeight: "700", marginBottom: 20 },
  step: { fontSize: 16, fontWeight: "600", marginTop: 20, marginBottom: 6 },
  body: { fontSize: 14, color: "#444", marginBottom: 10, lineHeight: 20 },
  mono: {
    fontFamily: "Courier", fontSize: 11, backgroundColor: "#f2f2f2",
    padding: 10, borderRadius: 6, marginBottom: 10,
  },
  input: {
    borderWidth: 1, borderColor: "#ccc", borderRadius: 6, padding: 10,
    fontFamily: "Courier", fontSize: 11, minHeight: 140, textAlignVertical: "top",
    marginBottom: 12,
  },
  section: { marginTop: 10 },
});
