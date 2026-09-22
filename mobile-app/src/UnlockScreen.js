import React, { useState, useEffect } from "react";
import { View, Text, TextInput, Button, StyleSheet, ActivityIndicator } from "react-native";
import * as SecureStore from "expo-secure-store";

import { attemptUnlock } from "./network";

const DEFAULT_PORT = "8765";
const HOST_KEY = "remote-unlock-last-host"; // not sensitive — just a convenience, no biometric gate
const PORT_KEY = "remote-unlock-last-port";

export default function UnlockScreen({ onRepair }) {
  const [host, setHost] = useState(""); // laptop's Tailscale or LAN IP, same one pair.py asked for
  const [port, setPort] = useState(DEFAULT_PORT);
  const [status, setStatus] = useState(null); // null | "working" | "success" | "fail"
  const [message, setMessage] = useState("");

  useEffect(() => {
    SecureStore.getItemAsync(HOST_KEY).then((v) => v && setHost(v));
    SecureStore.getItemAsync(PORT_KEY).then((v) => v && setPort(v));
  }, []);

  async function handleUnlock() {
    if (!host.trim()) {
      setMessage("Enter your laptop's IP first (Tailscale IP works from anywhere).");
      setStatus("fail");
      return;
    }
    setStatus("working");
    setMessage("");
    try {
      const ok = await attemptUnlock(host.trim(), parseInt(port, 10) || 8765);
      setStatus(ok ? "success" : "fail");
      setMessage(ok ? "Laptop unlocked." : "Laptop rejected the request.");
      if (ok) {
        // Only remember the host/port after a verified success, so a typo
        // or a stale IP doesn't get silently persisted.
        await SecureStore.setItemAsync(HOST_KEY, host.trim());
        await SecureStore.setItemAsync(PORT_KEY, port.trim());
      }
    } catch (e) {
      setStatus("fail");
      setMessage(e.message || "Something went wrong.");
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.title}>Unlock Laptop</Text>

      <Text style={styles.label}>Laptop IP (Tailscale or LAN)</Text>
      <TextInput
        style={styles.input}
        value={host}
        onChangeText={setHost}
        placeholder="100.x.x.x or 192.168.x.x"
        keyboardType="numbers-and-punctuation"
        autoCapitalize="none"
        autoCorrect={false}
      />

      <Text style={styles.label}>Port</Text>
      <TextInput
        style={styles.input}
        value={port}
        onChangeText={setPort}
        placeholder={DEFAULT_PORT}
        keyboardType="number-pad"
      />

      <View style={styles.buttonWrap}>
        {status === "working" ? (
          <ActivityIndicator size="large" />
        ) : (
          <Button title="Unlock my laptop" onPress={handleUnlock} />
        )}
      </View>

      {message ? (
        <Text style={status === "success" ? styles.success : styles.fail}>
          {message}
        </Text>
      ) : null}

      <View style={styles.footer}>
        <Button title="Re-pair" onPress={onRepair} color="#888" />
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 20, paddingTop: 80, backgroundColor: "#fff" },
  title: { fontSize: 26, fontWeight: "700", marginBottom: 30, textAlign: "center" },
  label: { fontSize: 13, color: "#666", marginBottom: 4, marginTop: 12 },
  input: {
    borderWidth: 1, borderColor: "#ccc", borderRadius: 8, padding: 12, fontSize: 16,
  },
  buttonWrap: { marginTop: 30 },
  success: { color: "#1e8e3e", textAlign: "center", marginTop: 20, fontSize: 15 },
  fail: { color: "#c0392b", textAlign: "center", marginTop: 20, fontSize: 15 },
  footer: { marginTop: 60, alignItems: "center" },
});
