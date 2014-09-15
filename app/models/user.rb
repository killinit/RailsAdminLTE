class User < ActiveRecord::Base
	before_save { self.email = email.downcase }
	before_create :create_remember_token
	validates :name,  presence: true, length: { maximum: 50 }
	VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(?:\.[a-z\d\-]+)*\.[a-z]+\z/i
	validates :email, presence: true,
		format: { with: VALID_EMAIL_REGEX },
		uniqueness: { case_sensitive: false }
	has_secure_password
	validates :password, length: { minimum: 6 }
	has_attached_file :avatar,
		:default_url  => "/avatars/default/:style/missing.png",
		:path         => ":rails_root/public/avatars/:class/:attachment/:id_partition/:style/:filename",
		:url          => "/avatars/:class/:attachment/:id_partition/:style/:basename.:extension"
	validates_attachment :avatar,
		:content_type => { :content_type => ["image/jpg", "image/jpeg", "image/png"] },
		:size => { :in => 10.kilobytes..50.kilobytes, :message => "must be in between 10KB and 50KB" }

	validates_attachment_content_type :avatar, :content_type => /\Aimage/

	def User.new_remember_token
		SecureRandom.urlsafe_base64
	end

	def User.digest(token)
		Digest::SHA1.hexdigest(token.to_s)
	end

	private

	def create_remember_token
		self.remember_token = User.digest(User.new_remember_token)
	end
end
