import React, { useState, useEffect } from "react";
import { View, ActivityIndicator } from "react-native";

import PairingScreen from "./src/PairingScreen";
import UnlockScreen from "./src/UnlockScreen";
import { getLaptopPublicKey, hasStoredKeypair } from "./src/secureStore";

export default function App() {
  const [loading, setLoading] = useState(true);
  const [paired, setPaired] = useState(false);

  useEffect(() => {
    checkPairing();
  }, []);

  async function checkPairing() {
    setLoading(true);
    const hasKeypair = await hasStoredKeypair();
    const hasLaptopKey = await getLaptopPublicKey();
    setPaired(Boolean(hasKeypair && hasLaptopKey));
    setLoading(false);
  }

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: "center", alignItems: "center" }}>
        <ActivityIndicator size="large" />
      </View>
    );
  }

  return paired ? (
    <UnlockScreen onRepair={() => setPaired(false)} />
  ) : (
    <PairingScreen onPaired={checkPairing} />
  );
}
