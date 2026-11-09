
import { supabase } from "./supabase.js";

try {
  const { data, error } = await supabase
    .from("events")
    .select("id")
    .limit(1);

  if (error) {
    throw error;
  }

  console.log("SUCCESS: Connected to Vigilix Supabase!");
  console.log("Events table is accessible.");
  console.log("Test result:", data);
} catch (error) {
  console.error("SUPABASE CONNECTION FAILED:");
  console.error(error.message);
  process.exitCode = 1;
}

