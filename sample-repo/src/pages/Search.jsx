import { useSearchParams } from "react-router-dom";

export default function Search() {
  const [params] = useSearchParams();
  const query = params.get("q");

  return (
    <section>
      <h1 dangerouslySetInnerHTML={{ __html: `Results for <em>${query}</em>` }} />
    </section>
  );
}
