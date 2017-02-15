Rails.application.routes.draw do

root :to => 'questions#index'

get "/log-in" => "sessions#new"
post "/log-in" => "sessions#create"
get "/log-out" => "sessions#destroy", as: :log_out #custom path


resources :users

resources :questions do
  resources :answers
end

end
