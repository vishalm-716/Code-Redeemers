// File: /api/v1/hackrx/run.js

export default function handler(request, response) {
  // Your application logic from the previous examples
  // ... (the code that processes the query and returns a decision)

  const { query } = request.body;

  if (!query) {
    return response.status(400).json({ error: 'Query is missing.' });
  }

  // Your processing logic...
  const result = {
    decision: "Approved",
    amount: 200000,
    justification: [{
      clause: "Clause 3.1: Standard surgical procedures, including knee replacement, are covered.",
      decision: "Approved"
    }]
  };

  // Send the response
  response.status(200).json(result);
}