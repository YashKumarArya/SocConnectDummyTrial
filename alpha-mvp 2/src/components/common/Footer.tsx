export default function Footer() {
  return (
    <footer className="border-t bg-white">
      <div className="mx-auto max-w-7xl px-4 py-4 text-sm text-gray-500">
        © {new Date().getFullYear()} YourApp. All rights reserved.
      </div>
    </footer>
  )
}
