import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export default function Admin({ user }) {
  const [users, setUsers] = useState([]);
  const isAdmin = localStorage.getItem("isAdmin") === "true";

  useEffect(() => {
    supabase.from("profiles").select("*").then(({ data }) => setUsers(data ?? []));
  }, []);

  async function deleteUser(id) {
    if (user.role === "admin") {
      await supabase.from("profiles").delete().eq("id", id);
      setUsers(users.filter((u) => u.id !== id));
    }
  }

  if (!isAdmin) return <p>Not allowed</p>;

  return (
    <table>
      <tbody>
        {users.map((u) => (
          <tr key={u.id}>
            <td>{u.email}</td>
            <td><button onClick={() => deleteUser(u.id)}>Delete</button></td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}
