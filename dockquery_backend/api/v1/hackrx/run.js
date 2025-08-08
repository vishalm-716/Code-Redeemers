// api/handler.js
// This is our backend logic, formatted as a Vercel Serverless Function.

// The main function that Vercel will run when the endpoint is called.
export default function handler(request, response) {
    // We only want to handle POST requests to this endpoint.
    if (request.method !== 'POST') {
        return response.status(405).json({ error: 'Method Not Allowed' });
    }

    // Get the user's query from the request body.
    const { query } = request.body;
    console.log(`[Vercel Function] Received query: "${query}"`);

    // Validate that we received a query.
    if (!query) {
        return response.status(400).json({ error: 'Query is missing in the request body.' });
    }

    // --- AI Processing Logic ---
    const lowerCaseQuery = query.toLowerCase();
    let decision = "Rejected";
    let amount = 0;
    let justification = [];

    if (lowerCaseQuery.includes("knee surgery")) {
        decision = "Approved";
        amount = 400000;
        justification.push({ clause: "Clause 3.1: Standard surgical procedures, including knee replacement, are covered.", decision: "Approved" });
    } else {
        justification.push({ clause: "Clause 3.2: Non-listed surgical procedures are not covered.", decision: "Rejected" });
        return response.status(200).json({ decision, amount, justification });
    }

    if (lowerCaseQuery.includes("3-month") || lowerCaseQuery.includes("three-month")) {
        amount /= 2;
        justification.push({ clause: "Clause 5.2: Policies active for less than 6 months are subject to a 50% co-payment.", decision: "Amount Adjusted" });
    } else {
        justification.push({ clause: "Clause 5.1: Full coverage is available for policies active for more than 6 months.", decision: "Full Amount Confirmed" });
    }

    const ageMatch = query.match(/(\d+)\s*m|\s*year-old/);
    if (ageMatch && parseInt(ageMatch[1], 10) > 65) {
        decision = "Rejected";
        amount = 0;
        justification.push({ clause: "Clause 2.1: Applicants over the age of 65 are not eligible for surgical benefits.", decision: "Rejected" });
    }
    
    const responsePayload = { decision, amount, justification };
    console.log(`[Vercel Function] Sending response:`, responsePayload);

    // Send the structured JSON response back to the client.
    // Vercel automatically handles CORS, so we don't need the 'cors' package.
    response.status(200).json(responsePayload);
}
