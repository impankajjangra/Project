# Use Nginx to serve static files
FROM nginx:alpine

# Copy HTML/CSS files
COPY ./templates /usr/share/nginx/html
COPY ./static /usr/share/nginx/html/static

# Expose port 80
EXPOSE 80

# Start Nginx
CMD ["nginx", "-g", "daemon off;"]