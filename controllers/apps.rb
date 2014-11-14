class WecheatApp

  before '/apps/:id*' do
    @app ||= Wecheat::Models::App.find(params[:id])
    halt(json errcode: 40012, errmsg: "invalid appid") if @app.nil?
  end

  get '/apps/:id' do
    erb :app, locals: { app: @app }
  end

  delete '/apps/:id' do
    @app.delete
    redirect to('/')
  end

  post '/apps/:id/test' do
    begin
      echostr = Wecheat::Utils.rand_secret
      echo = RestClient.get(app.base_url(echostr: echostr)).to_s.strip
      json error: (echostr != echo), response: echo
    rescue => e
      json error: true, response: e.inspect
    end
  end

  #update app
  put '/apps/:id' do
    unless params[:app].nil?
      [:token, :url, :label, :encoding_key].each do |attr|
        @app[attr] = params[:app][attr] unless params[:app][attr].nil?
      end
      @app.save
    end
    redirect to("/apps/#{@app.id}"), 302
  end

  get '/apps/:id/qrcodes/:openid' do
    erb :qrcodes, locals: { app: @app, user: @app.user(params[:openid]) }
  end

  get '/apps/:id/message' do
    erb :message, locals: { app: @app }
  end

  post '/apps/:id/message' do
    message = params[:message]
    user, type = @app.user(message[:user]), message[:type]
    halt 404 if user.nil?

    data = Wecheat::MessageBuilder.new.tap do |b|
      b.cdata 'ToUserName', @app.label
      b.cdata 'FromUserName', message[:user]
      b.cdata 'MsgType', type
      b.CreateTime Time.now.to_i
      b.MsgId Time.now.to_i

      case type
      when 'text' then b.cdata 'Content', message[:content]
      when 'link'
        b.cdata 'Url', message[:url]
        b.cdata 'Title', message[:title]
        b.cdata 'Description', message[:description]

      when 'location'
        b.cdata 'Location_X', user.longitude
        b.cdata 'Location_Y', user.latitude
        b.cdata 'Scale', message[:scale]
        b.cdata 'Label', message[:label]

      when 'image', 'video', 'voice'
        media = @app.media(message[:media_id]) || {}
        b.cdata 'MediaId', media[:id].to_s
        # image message
        b.cdata 'PicUrl', uri(media[:path].to_s) if type == 'image'

        #video message
        b.cdata 'ThumbMediaId', (@app.medias_by_type(:thumb).first || {})[:id] if type == 'video'

        #voice message
        b.cdata 'Format', 'mp3' if type == 'voice'

        #recognition of voice if present
        b.cdata 'Recognition', message[:recognition] if type == 'voice' && message[:recognition].to_s.strip != ''
      end
    end.to_xml

    timestamp      = Time.now.to_i
    nonce          = Wecheat::Utils.rand_secret
    msg_crypt      = Wecheat::MsgCrypt.new @app.id, @app.token, @app.encoding_key
    sig, msg       = *msg_crypt.encrypt(data, nonce, timestamp.to_s)
    params         = { timestamp: timestamp, nonce: nonce, msg_signature: sig }
    base_url       = @app.base_url params

    begin
      res = RestClient.post(base_url, msg, content_type: 'text/xml; charset=utf-8')
      # res = RestClient.post(@app.base_url, data, content_type: 'text/xml; charset=utf-8')
      res.force_encoding('utf-8') unless res.encoding.name == 'UTF-8'
      json error: false, response: res
    rescue => e
      json error: e
    end
  end

end
