/** @type {import('next').NextConfig} */
const nextConfig = {
  images: {
    remotePatterns: [
      {
        protocol: "https",
        hostname: "res.cloudinary.com",
      },
      {
        protocol: "https",
        hostname: "img.daisyui.com",
      },
    ],
  },
  staticPageGenerationTimeout: 300, // Increase timeout to 5 minutes
};

export default nextConfig;
