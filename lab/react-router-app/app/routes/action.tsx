import { redirect } from "react-router";

export async function action({ request }: { request: Request }) {
  const formData = await request.formData();
  const action = formData.get("action");

  console.log(`[SERVER ACTION] Received action: ${action}`);

  // Simulate processing
  return redirect("/");
}

export default function ActionPage() {
  return (
    <div>
      <h1>Action Endpoint</h1>
      <p>This endpoint processes server actions</p>
    </div>
  );
}
