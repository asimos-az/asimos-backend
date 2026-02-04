
async function notifyNearbyEmployers(alert, seekerName) {
    try {
        const lat = toNum(alert?.location_lat);
        const lng = toNum(alert?.location_lng);
        const radiusM = toNum(alert?.radius_m) || 10000; // default 10km if not set but passed
        const category = alert?.category;

        if (lat === null || lng === null) return { ok: false, reason: "no_alert_location" };
        if (!category) return { ok: false, reason: "no_category" };

        // Find employers with matching category
        const { data: employers, error } = await supabaseAdmin
            .from("profiles")
            .select("id, full_name, location, expo_push_token, company_name")
            .eq("role", "employer")
            .ilike("category", `%${category}%`); // flexible match

        if (error || !employers || employers.length === 0) return { ok: true, matched: 0 };

        const pushMessages = [];
        const historyRows = [];
        let matchCount = 0;

        for (const emp of employers) {
            const plat = toNum(emp.location?.lat);
            const plng = toNum(emp.location?.lng);
            if (plat === null || plng === null) continue;

            const d = haversineDistanceM(lat, lng, plat, plng);
            if (d <= radiusM) {
                matchCount++;
                const title = "Yeni işçi axtarışı";
                const body = `Yaxınlıqda (${Math.round(d)}m) ${seekerName || "bir nəfər"} ${category} işi axtarır.`;
                const dataPayload = { type: "alert_match", alertId: alert.id };

                // Priority: 1) push_tokens table, 2) profiles table
                // For simplicity, using profile token. In prod, fetch from push_tokens too.
                const userToken = emp.expo_push_token;

                if (userToken && String(userToken).startsWith("ExponentPushToken")) {
                    pushMessages.push({
                        to: userToken,
                        title,
                        body,
                        data: dataPayload,
                        sound: "default",
                        priority: "high"
                    });
                }
                historyRows.push({
                    user_id: emp.id,
                    title,
                    body,
                    data: dataPayload
                });
            }
        }

        if (pushMessages.length > 0) {
            sendExpoPush(pushMessages).catch(console.error);
        }
        if (historyRows.length > 0) {
            await insertNotifications(historyRows);
        }

        return { ok: true, matched: matchCount };
    } catch (e) {
        console.warn("notifyNearbyEmployers error", e);
        return { ok: false };
    }
}
