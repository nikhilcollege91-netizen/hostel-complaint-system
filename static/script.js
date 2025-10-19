// 🌟 Smooth redirect after registration or complaint submission
function redirectAfter(seconds, url) {
  setTimeout(() => {
    window.location.href = url;
  }, seconds * 1000);
}

// 💡 Show alert and redirect
function showSuccess(message, url) {
  alert(message);
  redirectAfter(3, url);
}

// ✨ Typewriter effect initialization (for homepage)
document.addEventListener("DOMContentLoaded", () => {
  const tagline = document.querySelector(".tagline");
  if (tagline) tagline.style.width = tagline.scrollWidth + "px";
});

// 📱 Mobile fix for iPhone safe area
window.addEventListener("load", () => {
  document.body.style.height = window.innerHeight + "px";
});
