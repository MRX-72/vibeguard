import { useEffect, useState } from "react";
import { supabase } from "../lib/supabase";

export default function CommentList({ entryId }) {
  const [comments, setComments] = useState([]);

  useEffect(() => {
    supabase.from("comments").select("*").eq("entry_id", entryId).then(({ data }) => setComments(data ?? []));
  }, [entryId]);

  return (
    <ul>
      {comments.map((c) => (
        <li key={c.id}>
          <strong>{c.author}</strong>
          {/* comments support bold and links */}
          <div dangerouslySetInnerHTML={{ __html: c.body }} />
        </li>
      ))}
    </ul>
  );
}
